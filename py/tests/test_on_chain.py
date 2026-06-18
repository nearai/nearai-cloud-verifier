"""Offline tests for on_chain.py.

Each test stubs ``on_chain._eth_call`` so the suite is hermetic
(no Base RPC calls).  Coverage:

  * happy path — every check passes
  * model→app_id mismatch
  * registeredApps returns false
  * allowedComposeHashes returns false
  * allowedOsImages returns false
  * KMS root pubkey mismatch
  * kmsInfo() returns empty bytes (current production state on Base)
  * RPC error is surfaced in errors[]
  * missing attestation fields are surfaced
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Make py/ importable when run from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import on_chain
from on_chain import (
    OnChainConfig,
    OnChainError,
    OnChainResult,
    _bool_from_word,
    _pack_address_arg,
    _pack_bytes32_arg,
    is_app_registered,
    is_compose_allowed,
    is_os_image_allowed,
    kms_root_pubkey,
    verify_on_chain_anchors,
    _SEL_REGISTERED_APPS,
    _SEL_ALLOWED_COMPOSE_HASHES,
    _SEL_ALLOWED_OS_IMAGES,
    _SEL_KMS_INFO_GETTER,
)


# ── Fixtures ────────────────────────────────────────────────────────────


KMS = "0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637"
APP = "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"
COMPOSE = "700adbf53ad4a14e58d2eae65776d451b914b1f5d377c20c7a4e6cca681446ec"
OS_IMG = "9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677"
KMS_ROOT_HEX = (
    "3059301306072a8648ce3d020106082a8648ce3d030107034200"
    "04228f800590a10442cba9d0e6adb2fa9f195eea9e75e23dd35990d52b59dda"
    "2415a63674c38adebde4ffd4d4b265bf818985933820c8053cee3ce29b5fb0fbcbc"
)


def _attestation(
    app_id: str = APP,
    compose: str = COMPOSE,
    os_image: str = OS_IMG,
    kpi_id: str = KMS_ROOT_HEX,
):
    return {
        "info": {
            "app_id": app_id,
            "compose_hash": compose,
            "os_image_hash": os_image,
            "key_provider_info": json.dumps({"name": "kms", "id": kpi_id}),
        },
    }


CONFIG = OnChainConfig(
    kms_contract_addr=KMS,
    rpc_url="http://stub-rpc/",
    chain_id=8453,
)


def _word(value: int) -> str:
    """Solidity 32-byte word, hex-encoded with 0x."""
    return "0x" + hex(value)[2:].rjust(64, "0")


def _kms_info_payload_full(
    k256: str = "", ca: str = "", quote: str = "", eventlog: str = ""
) -> str:
    """Build a kmsInfo() ABI-encoded return.  All four args are hex
    strings (no 0x); empty string = zero-length bytes."""
    parts = [k256, ca, quote, eventlog]
    lengths = [len(p) // 2 for p in parts]
    word_counts = [(L + 31) // 32 for L in lengths]
    padded = [
        p + "00" * (word_counts[i] * 32 - lengths[i]) for i, p in enumerate(parts)
    ]
    # Compute offsets (in bytes from start of return data)
    base = 4 * 32
    offsets = []
    cur = base
    for wc in word_counts:
        offsets.append(cur)
        cur += 32 + wc * 32
    out = ""
    for off in offsets:
        out += hex(off)[2:].rjust(64, "0")
    for i, L in enumerate(lengths):
        out += hex(L)[2:].rjust(64, "0") + padded[i]
    return "0x" + out


# Back-compat shim for older tests that only varied k256_pubkey.
def _kms_info_payload(k256_pubkey_hex: str) -> str:
    return _kms_info_payload_full(k256=k256_pubkey_hex)


# ── _eth_call stub helper ───────────────────────────────────────────────


class _Router:
    """Stub that dispatches eth_call by (to, selector) → response hex."""

    def __init__(self, routes):
        self.routes = routes

    def __call__(self, cfg, to, data):
        sel = data[:10]
        key = (to.lower(), sel)
        if key in self.routes:
            return self.routes[key]
        raise AssertionError(f"unexpected eth_call: to={to} sel={sel}")


def _route_all_pass(*, kms_pub_hex: str = KMS_ROOT_HEX):
    """Routes for the happy-path: all hard checks pass, kmsInfo
    populated with k256+quote+eventlog so kms_provenance succeeds.

    Set ``kms_pub_hex=""`` to simulate an uninitialized KMS contract.
    """
    if kms_pub_hex:
        kmsinfo = _kms_info_payload_full(
            k256=kms_pub_hex,
            ca="",
            quote="bb" * 100,  # non-empty placeholder for provenance
            eventlog="cc" * 50,
        )
    else:
        kmsinfo = _kms_info_payload_full()  # all empty
    return {
        (KMS.lower(), _SEL_REGISTERED_APPS): _word(1),
        (APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1),
        (KMS.lower(), _SEL_ALLOWED_OS_IMAGES): _word(1),
        (KMS.lower(), _SEL_KMS_INFO_GETTER): kmsinfo,
    }


# ── pure-helper tests (no network, no stubs) ────────────────────────────


def test_pack_address_arg_pads_to_32_bytes():
    out = _pack_address_arg("0xaBC0000000000000000000000000000000000123")
    assert len(out) == 64
    assert out.endswith("abc0000000000000000000000000000000000123")


def test_pack_address_arg_rejects_invalid():
    with pytest.raises(ValueError):
        _pack_address_arg("0xtooshort")


def test_pack_bytes32_arg_strips_0x():
    out = _pack_bytes32_arg(
        "0x" + "ab" * 32
    )
    assert out == "ab" * 32


def test_bool_from_word():
    assert _bool_from_word(_word(1)) is True
    assert _bool_from_word(_word(0)) is False


# ── individual reads ────────────────────────────────────────────────────


def test_is_app_registered_true():
    routes = {(KMS.lower(), _SEL_REGISTERED_APPS): _word(1)}
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        assert is_app_registered(CONFIG, APP) is True


def test_is_app_registered_false():
    routes = {(KMS.lower(), _SEL_REGISTERED_APPS): _word(0)}
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        assert is_app_registered(CONFIG, APP) is False


def test_is_compose_allowed_passes_app_addr_to_call():
    routes = {(APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1)}
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        assert is_compose_allowed(CONFIG, APP, COMPOSE) is True


def test_kms_root_pubkey_returns_bytes():
    routes = {(KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload(KMS_ROOT_HEX)}
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        out = kms_root_pubkey(CONFIG)
    assert out.hex() == KMS_ROOT_HEX


def test_kms_root_pubkey_empty_when_uninitialized():
    routes = {(KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload("")}
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        out = kms_root_pubkey(CONFIG)
    assert out == b""


# ── verify_on_chain_anchors composite ───────────────────────────────────


def test_verify_happy_path():
    with patch.object(on_chain, "_eth_call", _Router(_route_all_pass())):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is True, result.errors
    assert result.app_registered is True
    assert result.compose_allowed is True
    assert result.os_image_allowed is True
    assert result.kms_provenance is True
    assert result.model_app_id_matches is True
    assert result.errors == []


def test_verify_model_app_id_mismatch():
    other = "0x" + "11" * 20
    with patch.object(on_chain, "_eth_call", _Router(_route_all_pass())):
        result = verify_on_chain_anchors(
            _attestation(app_id=APP), CONFIG, expected_app_id=other
        )
    assert result.valid is False
    assert result.model_app_id_matches is False
    assert any("app_id" in e and "anchored" in e for e in result.errors)


def test_verify_app_not_registered():
    routes = _route_all_pass()
    routes[(KMS.lower(), _SEL_REGISTERED_APPS)] = _word(0)
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.app_registered is False
    assert any("registeredApps" in e and "false" in e for e in result.errors)


def test_verify_compose_not_allowed():
    routes = _route_all_pass()
    routes[(APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES)] = _word(0)
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.compose_allowed is False
    assert any("allowedComposeHashes" in e for e in result.errors)


def test_verify_os_image_not_allowed():
    routes = _route_all_pass()
    routes[(KMS.lower(), _SEL_ALLOWED_OS_IMAGES)] = _word(0)
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.os_image_allowed is False
    assert any("allowedOsImages" in e for e in result.errors)


def test_verify_kms_provenance_uninitialized_fails_closed():
    """Today's NEAR production state: kmsInfo().k256Pubkey is empty.

    The kms_provenance check is hard.  Without the on-chain attestation
    bundle (kmsInfo populated with quote+eventlog), the verifier
    cannot show the KMS root key was generated inside a TD.  Anyone
    with the private key can decrypt every E2EE prompt off-chain.
    Default ``require_kms_provenance=True`` fails closed.
    """
    routes = _route_all_pass(kms_pub_hex="")
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.kms_provenance is None
    assert any("kmsInfo" in e and "empty" in e for e in result.errors)


def test_verify_kms_provenance_permissive_mode_skips_check():
    """``require_kms_provenance=False`` lets the verification succeed
    despite a missing on-chain anchor.  This is the historical mode
    (trust the deployer's word) — used only as a transitional
    fallback.
    """
    cfg = OnChainConfig(
        kms_contract_addr=KMS,
        rpc_url="http://stub-rpc/",
        chain_id=8453,
        require_kms_provenance=False,
    )
    routes = _route_all_pass(kms_pub_hex="")
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), cfg, expected_app_id=APP)
    # Hard checks pass; provenance is None but permissive mode tolerates.
    assert result.valid is True
    assert result.kms_provenance is None


def test_verify_kms_provenance_pubkey_set_but_quote_missing_fails():
    """Mid-state: deployer set k256Pubkey but didn't include the quote.

    The contract has setKmsInfo / setKmsQuote / setKmsEventlog as
    separate setters, so partial population is possible.  Even with
    the pubkey set, no quote means no provenance.
    """
    routes = {
        (KMS.lower(), _SEL_REGISTERED_APPS): _word(1),
        (APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1),
        (KMS.lower(), _SEL_ALLOWED_OS_IMAGES): _word(1),
        # k256Pubkey set but quote+eventlog empty
        (KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload_full(
            k256=KMS_ROOT_HEX, ca="", quote="", eventlog=""
        ),
    }
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.kms_provenance is None
    assert any("quote is empty" in e or "Provenance unverifiable" in e for e in result.errors)


def test_verify_kms_provenance_full_kmsinfo_passes():
    """When kmsInfo is fully populated and the pubkey matches
    info.key_provider_info.id, provenance check passes.

    NOTE: This commit confirms the pubkey match; full TDX-quote
    verification of kmsInfo.quote is deferred to a follow-up.
    """
    routes = {
        (KMS.lower(), _SEL_REGISTERED_APPS): _word(1),
        (APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1),
        (KMS.lower(), _SEL_ALLOWED_OS_IMAGES): _word(1),
        (KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload_full(
            k256=KMS_ROOT_HEX,
            ca="aa" * 91,
            quote="bb" * 5006,
            eventlog="cc" * 100,
        ),
    }
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is True
    assert result.kms_provenance is True
    assert result.extracted["on_chain_kms_quote_len"] == 5006


def test_verify_kms_provenance_kpi_disagrees_with_onchain():
    """If on-chain kmsInfo.k256Pubkey is set AND attested via quote,
    but the CVM's info.key_provider_info.id reports a different
    pubkey, fail closed.
    """
    different_kpi = "ff" * (len(KMS_ROOT_HEX) // 2)
    routes = {
        (KMS.lower(), _SEL_REGISTERED_APPS): _word(1),
        (APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1),
        (KMS.lower(), _SEL_ALLOWED_OS_IMAGES): _word(1),
        (KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload_full(
            k256=KMS_ROOT_HEX,
            ca="",
            quote="bb" * 100,
            eventlog="cc" * 100,
        ),
    }
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(
            _attestation(kpi_id=different_kpi), CONFIG, expected_app_id=APP
        )
    assert result.valid is False
    assert result.kms_provenance is False
    assert any("key_provider_info.id" in e for e in result.errors)


def test_verify_rpc_error_surfaced():
    def boom(cfg, to, data):
        raise OnChainError("connection refused")

    with patch.object(on_chain, "_eth_call", boom):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    # All three on-chain checks should have errored; model-app match still ran.
    assert result.valid is False
    assert result.model_app_id_matches is True  # client/anchor comparison is local
    assert result.app_registered is None
    assert result.compose_allowed is None
    assert result.os_image_allowed is None
    assert len(result.errors) >= 3


def test_verify_missing_attestation_fields():
    bogus = {"info": {}}
    with patch.object(on_chain, "_eth_call", _Router({})):
        result = verify_on_chain_anchors(bogus, CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert any("missing one of" in e for e in result.errors)


def test_verify_requires_expected_app_id():
    with pytest.raises(ValueError, match="expected_app_id is required"):
        verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=None)


def test_verify_extracts_kpi_from_string_or_dict():
    # key_provider_info as already-parsed dict
    att = _attestation()
    att["info"]["key_provider_info"] = {"name": "kms", "id": KMS_ROOT_HEX}
    with patch.object(on_chain, "_eth_call", _Router(_route_all_pass())):
        result = verify_on_chain_anchors(att, CONFIG, expected_app_id=APP)
    assert result.valid is True
