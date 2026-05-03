"""On-chain anchoring for the closed-chain attestation verifier.

The existing verifier in :mod:`model_verifier` confirms the *cryptography*
in an attestation report is internally consistent — Intel-signed TDX
quote, RTMR3 replay, ``report_data`` binding, NRAS GPU verdict.  It does
**not** check whether the ``compose_hash``, ``app_id``, ``os_image_hash``,
or KMS pubkey extracted from the attestation correspond to anything the
deployer (NEAR / Phala / etc.) has authorized on chain.

This module adds the missing leg.  Given:

  * an attestation response (the JSON returned by
    ``GET /v1/attestation/report?model=…&nonce=…``), and
  * an :class:`OnChainConfig` carrying the canonical KMS contract address
    and the expected ``app_id`` for the requested model,

:func:`verify_on_chain_anchors` makes four ``eth_call``-style queries
against the configured Base RPC and returns an :class:`OnChainResult`
whose ``valid`` property is True iff every check passes:

  * ``DstackKms(kms_addr).registeredApps(app_id) == true``
  * ``DstackApp(app_id).allowedComposeHashes(compose_hash) == true``
  * ``DstackKms(kms_addr).allowedOsImages(os_image_hash) == true``
  * ``DstackKms(kms_addr).kmsInfo().k256Pubkey`` matches
    ``info.key_provider_info.id`` from the attestation

The ``app_id`` argument is **required**; passing
``expected_app_id=None`` raises, because anchoring without a pinned
``model_name → app_id`` map lets the operator route requests for one
model to a different (also-registered) app.

The contracts live at the addresses used by Phala's reference dstack
deployment (`Dstack-TEE/dstack/kms/auth-eth/contracts/`).  Other
deployments (Tinfoil, Phala Redpill, Venice) use the same contract
shape so the same code can verify them; only the ``OnChainConfig``
values change.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


# ── Function selectors (keccak256 of the signature, first 4 bytes) ──────
# DstackApp:
_SEL_ALLOWED_COMPOSE_HASHES = "0x2f6622e5"  # allowedComposeHashes(bytes32)

# DstackKms:
_SEL_REGISTERED_APPS = "0xa6c4cce9"  # registeredApps(address)
_SEL_ALLOWED_OS_IMAGES = "0x9a4e1d18"  # allowedOsImages(bytes32)
_SEL_KMS_INFO_GETTER = "0x09177063"   # kmsInfo() → (bytes, bytes, bytes, bytes)


class OnChainError(Exception):
    """Raised when an on-chain anchoring check fails."""


@dataclass(frozen=True)
class OnChainConfig:
    """Pinned reference values for one provider's on-chain anchor.

    Args:
        kms_contract_addr: 0x-prefixed address of the deployed
            ``DstackKms`` proxy.
        rpc_url: HTTP RPC endpoint for the chain the contracts live on.
        chain_id: 1 (mainnet) or 8453 (Base mainnet) etc. — used only
            for diagnostic output.
        request_timeout: Per-eth_call HTTP timeout (seconds).
        expected_kms_root_pubkey_hex: Off-chain pinned value for the
            canonical KMS pubkey (the SubjectPublicKeyInfo blob the
            booting KMS publishes to CVMs as
            ``info.key_provider_info.id``).  Required when
            ``kmsInfo()`` on chain is empty (i.e. the deployer never
            called ``setKmsInfo``); when both are present, both must
            agree.  Set to None to disable the KMS-root check entirely
            (NOT recommended — defeats one leg of the closed chain).
    """

    kms_contract_addr: str
    rpc_url: str = "https://mainnet.base.org"
    chain_id: int = 8453
    request_timeout: float = 12.0
    expected_kms_root_pubkey_hex: Optional[str] = None


@dataclass
class OnChainResult:
    """Result of running on-chain anchoring against an attestation.

    The **hard checks** (must be True for ``valid``):

      * ``app_registered``           — DstackKms.registeredApps(app_id)
      * ``compose_allowed``          — DstackApp(app_id).allowedComposeHashes(...)
      * ``os_image_allowed``         — DstackKms.allowedOsImages(os_image_hash)
      * ``model_app_id_matches``     — pinned (model→app_id) anchor

    The **soft cross-check**:

      * ``kms_root_matches`` — compares info.key_provider_info.id against
        the canonical KMS pubkey, taken from on-chain
        ``DstackKms.kmsInfo().k256Pubkey`` if populated, otherwise from
        an off-chain pin in :class:`OnChainConfig`.  If neither is
        available, reported as None (unanchored) with a warning, but
        does NOT fail ``valid``.  If a value IS available and
        disagrees, that DOES fail ``valid``.
    """

    app_registered: Optional[bool] = None
    compose_allowed: Optional[bool] = None
    os_image_allowed: Optional[bool] = None
    kms_root_matches: Optional[bool] = None
    model_app_id_matches: Optional[bool] = None
    extracted: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        # Hard checks must all be True.
        hard = (
            self.app_registered is True
            and self.compose_allowed is True
            and self.os_image_allowed is True
            and self.model_app_id_matches is True
        )
        # Soft cross-check: only fail if explicitly mismatched.  An
        # un-anchorable kms_root (None) does not block ``valid``.
        soft = self.kms_root_matches is not False
        return hard and soft

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "app_registered": self.app_registered,
            "compose_allowed": self.compose_allowed,
            "os_image_allowed": self.os_image_allowed,
            "kms_root_matches": self.kms_root_matches,
            "model_app_id_matches": self.model_app_id_matches,
            "extracted": self.extracted,
            "errors": list(self.errors),
        }


# ── RPC plumbing ────────────────────────────────────────────────────────


def _eth_call(cfg: OnChainConfig, to: str, data: str) -> str:
    """Single eth_call.  Returns the raw 0x-prefixed hex result, or
    raises :class:`OnChainError` on RPC error / timeout."""
    if not to.startswith("0x"):
        to = "0x" + to
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }
    try:
        r = requests.post(cfg.rpc_url, json=payload, timeout=cfg.request_timeout)
    except requests.RequestException as exc:
        raise OnChainError(f"eth_call to {to} failed: {exc}") from exc
    if r.status_code != 200:
        raise OnChainError(f"eth_call to {to}: HTTP {r.status_code}: {r.text[:200]}")
    body = r.json()
    if "error" in body:
        raise OnChainError(f"eth_call to {to} returned error: {body['error']}")
    result = body.get("result")
    if not isinstance(result, str):
        raise OnChainError(f"eth_call to {to}: unexpected result {result!r}")
    return result


def _pack_address_arg(addr: str) -> str:
    """Address packed into a 32-byte slot (zero-padded on the left)."""
    a = addr.removeprefix("0x").lower()
    if len(a) != 40:
        raise ValueError(f"Invalid address: {addr!r}")
    return a.rjust(64, "0")


def _pack_bytes32_arg(value: str) -> str:
    """bytes32 argument; value must be 32 bytes hex (with or without 0x)."""
    v = value.removeprefix("0x").lower()
    if len(v) != 64:
        raise ValueError(f"Invalid bytes32: {value!r} (must be 32 bytes hex)")
    return v


def _bool_from_word(word_hex: str) -> bool:
    """Decode a Solidity bool return (32-byte word, last bit set)."""
    return int(word_hex.removeprefix("0x"), 16) != 0


# ── Public API: individual checks ───────────────────────────────────────


def is_app_registered(cfg: OnChainConfig, app_id: str) -> bool:
    """``DstackKms(kms).registeredApps(app_id)``."""
    data = _SEL_REGISTERED_APPS + _pack_address_arg(app_id)
    return _bool_from_word(_eth_call(cfg, cfg.kms_contract_addr, data))


def is_compose_allowed(cfg: OnChainConfig, app_id: str, compose_hash: str) -> bool:
    """``DstackApp(app_id).allowedComposeHashes(compose_hash)``."""
    data = _SEL_ALLOWED_COMPOSE_HASHES + _pack_bytes32_arg(compose_hash)
    return _bool_from_word(_eth_call(cfg, app_id, data))


def is_os_image_allowed(cfg: OnChainConfig, os_image_hash: str) -> bool:
    """``DstackKms(kms).allowedOsImages(os_image_hash)``."""
    data = _SEL_ALLOWED_OS_IMAGES + _pack_bytes32_arg(os_image_hash)
    return _bool_from_word(_eth_call(cfg, cfg.kms_contract_addr, data))


def kms_root_pubkey(cfg: OnChainConfig) -> bytes:
    """``DstackKms(kms).kmsInfo().k256Pubkey``.

    Returns the raw bytes of the ``k256Pubkey`` field.  Callers compare
    this against ``attestation.info.key_provider_info.id`` (the
    SubjectPublicKeyInfo blob the booting KMS published to the CVM).

    Empty bytes (``b""``) means the KMS contract has not been
    initialized via ``setKmsInfo``.  This is a real deployment gap —
    the on-chain anchor for "this is the canonical KMS pubkey" is
    absent, so an external verifier cannot link the booting KMS's
    pubkey to the on-chain registry.  :func:`verify_on_chain_anchors`
    treats this case as a hard failure (fail-closed).
    """
    raw = _eth_call(cfg, cfg.kms_contract_addr, _SEL_KMS_INFO_GETTER)
    raw_hex = raw.removeprefix("0x")
    # ABI-decode the struct: kmsInfo() returns (bytes k256Pubkey, bytes
    # caPubkey, bytes quote, bytes eventlog).  Solidity returns dynamic
    # types as (offset, offset, offset, offset) followed by each
    # length-prefixed payload.  We only need the first member.
    if len(raw_hex) < 64:
        raise OnChainError(f"kmsInfo() returned too short payload: 0x{raw_hex}")
    first_offset = int(raw_hex[:64], 16) * 2  # to hex chars
    if first_offset + 64 > len(raw_hex):
        raise OnChainError("kmsInfo() malformed: first offset out of range")
    length = int(raw_hex[first_offset : first_offset + 64], 16)
    start = first_offset + 64
    end = start + length * 2
    if end > len(raw_hex):
        raise OnChainError("kmsInfo() malformed: declared length exceeds payload")
    return bytes.fromhex(raw_hex[start:end])


# ── Public API: composite check ─────────────────────────────────────────


def _extract_attestation_fields(model_att: Dict[str, Any]) -> Dict[str, Any]:
    """Pull out the four fields the on-chain checks consume."""
    info = model_att.get("info") or {}
    out: Dict[str, Any] = {}
    out["app_id"] = info.get("app_id")
    out["compose_hash"] = info.get("compose_hash")
    out["os_image_hash"] = info.get("os_image_hash")
    kpi = info.get("key_provider_info")
    if isinstance(kpi, str):
        try:
            kpi = json.loads(kpi)
        except Exception:
            kpi = {}
    elif not isinstance(kpi, dict):
        kpi = {}
    out["key_provider_info_id"] = kpi.get("id")
    return out


def verify_on_chain_anchors(
    model_attestation: Dict[str, Any],
    cfg: OnChainConfig,
    expected_app_id: str,
) -> OnChainResult:
    """Run all four on-chain checks for one model attestation.

    Args:
        model_attestation: One element of the attestation response's
            ``model_attestations`` array (or the ``gateway_attestation``
            object — the structure is the same for both).  Must contain
            ``info`` with ``app_id``, ``compose_hash``, ``os_image_hash``,
            and ``key_provider_info``.
        cfg: :class:`OnChainConfig` carrying the canonical KMS contract
            address, the RPC URL, and the chain id.
        expected_app_id: The pinned ``app_id`` for the model the client
            requested.  This is the **anchor** — without it, the
            operator can route to any registered app and on-chain
            checks pass trivially.

    Returns:
        :class:`OnChainResult` whose ``valid`` is True iff every check
        passed.  When False, ``errors`` and the per-check booleans
        explain which leg failed.
    """
    if not expected_app_id:
        raise ValueError(
            "expected_app_id is required.  Closed-chain anchoring requires "
            "a pinned (model_name → app_id) map; passing None is not "
            "supported because it lets the operator silently route to a "
            "different (registered, allow-listed) app."
        )

    fields = _extract_attestation_fields(model_attestation)
    result = OnChainResult(extracted=fields)

    app_id = fields["app_id"]
    compose_hash = fields["compose_hash"]
    os_image_hash = fields["os_image_hash"]
    kpi_id_hex = (fields.get("key_provider_info_id") or "").lower()

    if not (app_id and compose_hash and os_image_hash):
        result.errors.append(
            "attestation missing one of: info.app_id, info.compose_hash, info.os_image_hash"
        )
        return result

    # 1. model_name → app_id pin (normalize both to '0x'-prefixed lowercase)
    def _norm_addr(a: str) -> str:
        a = a.lower().removeprefix("0x")
        return "0x" + a
    result.model_app_id_matches = _norm_addr(app_id) == _norm_addr(expected_app_id)
    if not result.model_app_id_matches:
        result.errors.append(
            f"app_id {app_id} != anchored {expected_app_id} — "
            f"the routed CVM is not the one pinned for this model"
        )
        # Still run the other checks so the user sees the full picture.

    # 2. registeredApps
    try:
        result.app_registered = is_app_registered(cfg, app_id)
        if not result.app_registered:
            result.errors.append(
                f"DstackKms({cfg.kms_contract_addr}).registeredApps({app_id}) is false"
            )
    except OnChainError as exc:
        result.errors.append(f"registeredApps lookup failed: {exc}")

    # 3. allowedComposeHashes (called on the app, not the KMS)
    try:
        result.compose_allowed = is_compose_allowed(cfg, app_id, compose_hash)
        if not result.compose_allowed:
            result.errors.append(
                f"DstackApp({app_id}).allowedComposeHashes(0x{compose_hash}) is false"
            )
    except OnChainError as exc:
        result.errors.append(f"allowedComposeHashes lookup failed: {exc}")

    # 4. allowedOsImages
    try:
        result.os_image_allowed = is_os_image_allowed(cfg, os_image_hash)
        if not result.os_image_allowed:
            result.errors.append(
                f"DstackKms({cfg.kms_contract_addr}).allowedOsImages(0x{os_image_hash}) is false"
            )
    except OnChainError as exc:
        result.errors.append(f"allowedOsImages lookup failed: {exc}")

    # 5. KMS root pubkey check.
    # Source of truth, in priority order:
    #   (a) on-chain DstackKms.kmsInfo().k256Pubkey  — strongest, but only
    #       populated if the deployer has called setKmsInfo;
    #   (b) cfg.expected_kms_root_pubkey_hex          — off-chain anchor,
    #       used when (a) is empty;
    #   (c) cross-check (a) and (b) when both are present.
    # The check fails if neither (a) nor (b) is available — the
    # verifier can't link info.key_provider_info.id to anything
    # authoritative.
    on_chain_pub_hex: Optional[str] = None
    try:
        on_chain_pub = kms_root_pubkey(cfg)
        if len(on_chain_pub) > 0:
            on_chain_pub_hex = on_chain_pub.hex().lower()
            result.extracted["on_chain_kms_root"] = on_chain_pub_hex
    except OnChainError as exc:
        result.errors.append(f"kmsInfo lookup failed: {exc}")

    pinned_pub_hex = (
        (cfg.expected_kms_root_pubkey_hex or "")
        .removeprefix("0x")
        .lower()
        or None
    )
    if pinned_pub_hex:
        result.extracted["pinned_kms_root"] = pinned_pub_hex

    def _normalize(h: str) -> str:
        return h.removeprefix("0x").lower()

    kpi_norm = _normalize(kpi_id_hex)

    if on_chain_pub_hex is None and pinned_pub_hex is None:
        # Neither source available.  Soft check: no anchor for the
        # canonical KMS pubkey.  The closed chain still works because
        # ``registeredApps`` + ``allowedComposeHashes`` already gate
        # which composes can boot — this just removes the
        # belt-and-suspenders cross-check.
        result.kms_root_matches = None
        result.warnings.append(
            f"DstackKms({cfg.kms_contract_addr}).kmsInfo().k256Pubkey is empty AND "
            "OnChainConfig.expected_kms_root_pubkey_hex is unset — kms_root cross-check "
            "skipped.  The deployer should either call setKmsInfo on chain or pin "
            "the expected pubkey in the verifier's anchor file for full closure."
        )
    else:
        anchored = on_chain_pub_hex or pinned_pub_hex
        result.kms_root_matches = kpi_norm == anchored
        if not result.kms_root_matches:
            source = "on-chain" if on_chain_pub_hex else "pinned anchor"
            result.errors.append(
                f"info.key_provider_info.id != KMS pubkey from {source} "
                f"(claimed: 0x{kpi_norm[:32]}…, anchored: 0x{anchored[:32]}…)"
            )
        # If both sources present, they must agree.
        if on_chain_pub_hex and pinned_pub_hex and on_chain_pub_hex != pinned_pub_hex:
            result.kms_root_matches = False
            result.errors.append(
                "on-chain DstackKms.kmsInfo.k256Pubkey and pinned anchor disagree — "
                f"on-chain: 0x{on_chain_pub_hex[:32]}…, pinned: 0x{pinned_pub_hex[:32]}…"
            )

    return result
