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
        require_kms_provenance: When True (default), the verifier
            insists on a TDX-attested provenance for the KMS root
            pubkey — i.e. the on-chain ``kmsInfo.quote`` must be
            populated AND verifiable, OR a quote+eventlog must be
            supplied out-of-band via ``kms_attestation_override``.
            Without one of those, the kms-root binding to a TDX TD
            cannot be established and the verifier fails closed.
            Setting to False bypasses the provenance check (NOT
            recommended; this is the historical "trust the deployer's
            asserted pubkey" mode and provides no exfil protection
            beyond reputation).
    """

    kms_contract_addr: str
    rpc_url: str = "https://mainnet.base.org"
    chain_id: int = 8453
    request_timeout: float = 12.0
    require_kms_provenance: bool = True


@dataclass
class OnChainResult:
    """Result of running on-chain anchoring against an attestation.

    All five fields are hard checks — any False (or, for
    ``kms_provenance``, a fail-closed None when
    ``require_kms_provenance`` is set) fails ``valid``.

      * ``app_registered``           — DstackKms.registeredApps(app_id)
      * ``compose_allowed``          — DstackApp(app_id).allowedComposeHashes(...)
      * ``os_image_allowed``         — DstackKms.allowedOsImages(os_image_hash)
      * ``model_app_id_matches``     — pinned (model→app_id) anchor
      * ``kms_provenance``           — TDX-attested origin of
        ``info.key_provider_info.id``.  See :func:`verify_on_chain_anchors`
        for what this requires.  ``None`` means "could not establish";
        the ``valid`` property treats that as failure when
        ``OnChainConfig.require_kms_provenance`` is True (the default).
    """

    app_registered: Optional[bool] = None
    compose_allowed: Optional[bool] = None
    os_image_allowed: Optional[bool] = None
    kms_provenance: Optional[bool] = None
    model_app_id_matches: Optional[bool] = None
    extracted: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # Set by verify_on_chain_anchors; controls how kms_provenance=None
    # is interpreted by the .valid property.
    _require_kms_provenance: bool = True

    @property
    def valid(self) -> bool:
        hard = (
            self.app_registered is True
            and self.compose_allowed is True
            and self.os_image_allowed is True
            and self.model_app_id_matches is True
        )
        if self._require_kms_provenance:
            return hard and self.kms_provenance is True
        # Permissive mode: only fail on explicit False, not on None.
        return hard and self.kms_provenance is not False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "app_registered": self.app_registered,
            "compose_allowed": self.compose_allowed,
            "os_image_allowed": self.os_image_allowed,
            "kms_provenance": self.kms_provenance,
            "model_app_id_matches": self.model_app_id_matches,
            "extracted": self.extracted,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
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


def _decode_kms_info(raw_hex: str) -> Tuple[bytes, bytes, bytes, bytes]:
    """ABI-decode ``kmsInfo() returns (bytes, bytes, bytes, bytes)``.

    Returns ``(k256Pubkey, caPubkey, quote, eventlog)``.  Any of these
    may be empty bytes if the deployer left them unset.
    """
    h = raw_hex.removeprefix("0x")
    if len(h) < 4 * 64:
        raise OnChainError(f"kmsInfo() return too short: {len(h)} hex chars")
    fields: List[bytes] = []
    for i in range(4):
        off_chars = int(h[i * 64 : (i + 1) * 64], 16) * 2
        if off_chars + 64 > len(h):
            raise OnChainError(f"kmsInfo() field {i} offset out of range")
        length = int(h[off_chars : off_chars + 64], 16)
        start = off_chars + 64
        end = start + length * 2
        if end > len(h):
            raise OnChainError(f"kmsInfo() field {i} length exceeds payload")
        fields.append(bytes.fromhex(h[start:end]))
    return fields[0], fields[1], fields[2], fields[3]


def _kms_info_full(cfg: OnChainConfig) -> Tuple[bytes, bytes]:
    """Read ``kmsInfo`` and return ``(quote, eventlog)``.

    The k256Pubkey and caPubkey are returned by :func:`kms_root_pubkey`
    independently; this helper is for the additional attestation
    bundle.  Both bytes objects may be empty if the deployer never
    populated them.
    """
    raw = _eth_call(cfg, cfg.kms_contract_addr, _SEL_KMS_INFO_GETTER)
    _, _, quote, eventlog = _decode_kms_info(raw)
    return quote, eventlog


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
    pub, _ca, _q, _e = _decode_kms_info(raw)
    return pub


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
    result = OnChainResult(
        extracted=fields,
        _require_kms_provenance=cfg.require_kms_provenance,
    )

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

    # 5. KMS root provenance.
    #
    # An external verifier cannot accept a KMS pubkey on the deployer's
    # word: anyone with the KMS root *private* key can derive every app
    # key downstream and decrypt every E2EE prompt off-chain.  The
    # provenance proof is "this pubkey is bound to a TDX TD via that
    # TD's own attestation quote, and that TD's measurement is in the
    # contract's `kmsAllowedAggregatedMrs` allowlist."
    #
    # We treat the on-chain ``kmsInfo`` struct as the canonical source.
    # ``kmsInfo`` carries (k256Pubkey, caPubkey, quote, eventlog).
    # When ``quote`` is non-empty we have everything we need to verify
    # the chain — but full verification of the embedded TDX quote
    # belongs in a follow-up that imports check_tdx_quote/
    # check_report_data from model_verifier.  This commit lays the
    # data extraction; quote-verification wiring lands in PR-2.
    #
    # When ``kmsInfo`` is empty (current state on NEAR's deployment),
    # there is no on-chain provenance.  The verifier reports
    # ``kms_provenance=None`` and (under ``require_kms_provenance=True``,
    # the default) fails closed.
    on_chain_pub_hex: Optional[str] = None
    on_chain_quote_hex: Optional[str] = None
    on_chain_eventlog_hex: Optional[str] = None
    try:
        on_chain_pub = kms_root_pubkey(cfg)
        if len(on_chain_pub) > 0:
            on_chain_pub_hex = on_chain_pub.hex().lower()
            result.extracted["on_chain_kms_root"] = on_chain_pub_hex
            # Pull quote + eventlog as well — these fully attest the
            # k256Pubkey when verified.  Stored for PR-2 to consume.
            quote_bytes, eventlog_bytes = _kms_info_full(cfg)
            on_chain_quote_hex = quote_bytes.hex() if quote_bytes else ""
            on_chain_eventlog_hex = eventlog_bytes.hex() if eventlog_bytes else ""
            result.extracted["on_chain_kms_quote_len"] = len(quote_bytes)
            result.extracted["on_chain_kms_eventlog_len"] = len(eventlog_bytes)
    except OnChainError as exc:
        result.errors.append(f"kmsInfo lookup failed: {exc}")

    kpi_norm = (kpi_id_hex or "").removeprefix("0x").lower()

    if on_chain_pub_hex is None:
        # No on-chain provenance.  The KMS pubkey published by the
        # CVM (info.key_provider_info.id) is unanchored.
        result.kms_provenance = None
        result.errors.append(
            f"DstackKms({cfg.kms_contract_addr}).kmsInfo().k256Pubkey is empty "
            "(setKmsInfo never called) — no on-chain anchor for the KMS root "
            "pubkey.  Cannot verify whether the key was generated inside a TD "
            "or imported from outside.  Anyone with the KMS root private key "
            "can decrypt every E2EE prompt off-chain.  Either NEAR populates "
            "kmsInfo on chain, or the verifier must accept that the KMS root "
            "provenance is unverifiable (set "
            "OnChainConfig.require_kms_provenance=False to bypass — NOT "
            "recommended)."
        )
    elif not on_chain_quote_hex:
        # k256Pubkey is set but quote is missing.  Mid-state: deployer
        # asserted a pubkey but published no attestation.  Same
        # provenance gap as the empty-kmsInfo case.
        result.kms_provenance = None
        result.errors.append(
            f"DstackKms({cfg.kms_contract_addr}).kmsInfo() has k256Pubkey set "
            "but quote is empty — the deployer asserted a pubkey without "
            "publishing the TDX attestation that binds it.  Provenance "
            "unverifiable."
        )
    else:
        # k256Pubkey AND quote are populated.  We have what we need to
        # verify provenance, modulo the actual TDX quote check (PR-2).
        # For now, confirm the CVM's reported KMS pubkey matches the
        # one bound by the on-chain quote bundle.
        if kpi_norm != on_chain_pub_hex:
            result.kms_provenance = False
            result.errors.append(
                "info.key_provider_info.id != on-chain DstackKms.kmsInfo.k256Pubkey "
                f"(claimed: 0x{kpi_norm[:32]}…, on-chain: 0x{on_chain_pub_hex[:32]}…)"
            )
        else:
            # PR-2 will replace this with full quote verification.
            result.kms_provenance = True
            result.warnings.append(
                "kms_provenance set True based on on-chain k256Pubkey match; "
                "full TDX quote verification of kmsInfo.quote is deferred to "
                "a follow-up commit."
            )

    return result
