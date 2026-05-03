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


def _kms_info_payload(k256_pubkey_hex: str) -> str:
    """Build a kmsInfo() return: (k256, ca, quote, eventlog) all bytes.

    Returns the 0x-prefixed hex of the ABI-encoded tuple.  Only the
    first member's content is variable; the others are zero-length.
    """
    pub = k256_pubkey_hex
    pub_bytes = len(pub) // 2
    pub_words = (pub_bytes + 31) // 32
    pub_padded = pub + "00" * (pub_words * 32 - pub_bytes)
    # Four offsets (each 32B), then for each member: length(32B)+padded data
    # Calculate offsets
    base = 4 * 32  # bytes after the four offsets
    off1 = base
    off2 = off1 + 32 + pub_words * 32
    off3 = off2 + 32  # zero-length
    off4 = off3 + 32  # zero-length
    payload = (
        hex(off1)[2:].rjust(64, "0")
        + hex(off2)[2:].rjust(64, "0")
        + hex(off3)[2:].rjust(64, "0")
        + hex(off4)[2:].rjust(64, "0")
        + hex(pub_bytes)[2:].rjust(64, "0")
        + pub_padded
        + "00" * 32  # caPubkey length=0
        + "00" * 32  # quote length=0
        + "00" * 32  # eventlog length=0
    )
    return "0x" + payload


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
    return {
        (KMS.lower(), _SEL_REGISTERED_APPS): _word(1),
        (APP.lower(), _SEL_ALLOWED_COMPOSE_HASHES): _word(1),
        (KMS.lower(), _SEL_ALLOWED_OS_IMAGES): _word(1),
        (KMS.lower(), _SEL_KMS_INFO_GETTER): _kms_info_payload(kms_pub_hex),
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
    assert result.kms_root_matches is True
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


def test_verify_kms_root_mismatch():
    different = "f" * len(KMS_ROOT_HEX)
    routes = _route_all_pass(kms_pub_hex=different)
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is False
    assert result.kms_root_matches is False
    assert any("key_provider_info.id" in e for e in result.errors)


def test_verify_kms_root_uninitialized_warns_but_still_valid():
    """Today's NEAR production state: kmsInfo().k256Pubkey is empty.

    The kms_root check is a *cross-check*, not load-bearing — the closed
    chain still holds via registeredApps + allowedComposeHashes +
    allowedOsImages + the model→app_id anchor.  When kmsInfo is empty
    AND no off-chain anchor is pinned, kms_root_matches is None
    (unanchored) with a warning, and the overall result remains valid.
    """
    routes = _route_all_pass(kms_pub_hex="")
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), CONFIG, expected_app_id=APP)
    assert result.valid is True
    assert result.kms_root_matches is None
    assert any("kmsInfo" in w and "skipped" in w for w in result.warnings)


def test_verify_kms_root_uninitialized_with_pinned_anchor_passes():
    """When on-chain kmsInfo is empty but the anchor file pins the
    expected KMS pubkey, kms_root_matches is decided against the pin.
    """
    cfg = OnChainConfig(
        kms_contract_addr=KMS,
        rpc_url="http://stub-rpc/",
        chain_id=8453,
        expected_kms_root_pubkey_hex=KMS_ROOT_HEX,
    )
    routes = _route_all_pass(kms_pub_hex="")
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), cfg, expected_app_id=APP)
    assert result.valid is True
    assert result.kms_root_matches is True


def test_verify_kms_root_pinned_anchor_disagrees_with_attestation():
    """If the anchor file pins a pubkey that disagrees with
    info.key_provider_info.id, fail closed.
    """
    cfg = OnChainConfig(
        kms_contract_addr=KMS,
        rpc_url="http://stub-rpc/",
        chain_id=8453,
        expected_kms_root_pubkey_hex="ff" * 32,
    )
    routes = _route_all_pass(kms_pub_hex="")
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), cfg, expected_app_id=APP)
    assert result.valid is False
    assert result.kms_root_matches is False
    assert any("pinned anchor" in e for e in result.errors)


def test_verify_kms_root_onchain_and_pinned_must_agree():
    """If both sources are present, they must agree."""
    cfg = OnChainConfig(
        kms_contract_addr=KMS,
        rpc_url="http://stub-rpc/",
        chain_id=8453,
        expected_kms_root_pubkey_hex="aa" * 32,
    )
    routes = _route_all_pass(kms_pub_hex=KMS_ROOT_HEX)
    with patch.object(on_chain, "_eth_call", _Router(routes)):
        result = verify_on_chain_anchors(_attestation(), cfg, expected_app_id=APP)
    assert result.valid is False
    assert result.kms_root_matches is False
    assert any("disagree" in e for e in result.errors)


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
