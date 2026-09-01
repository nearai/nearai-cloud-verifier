"""Cloud API Gateway and model-attestation verification flows.

The two functions in this module intentionally verify different targets:

* Gateway evidence proves the Gateway TEE deployment and the TLS peer that
  returned that evidence.
* Model evidence proves a model-serving TEE deployment and its GPU evidence.

Neither independent attestation establishes a relationship to a particular
completion. ``completion.py`` adds that relationship only after it reads the
completion's ``signature_kind`` and verifies the exact signed bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from py.utils.attestation import (
    AttestationVerificationError,
    VerificationFailure,
    decode_hex,
    verify_dstack_deployment,
    verify_dstack_quote,
    verify_nvidia_evidence,
    verify_report_data_binding,
    verify_report_data_binding_with_tls_fingerprint,
)


@dataclass(frozen=True)
class VerifiedModelAttestation:
    """Model evidence that has passed every model-attestation check."""

    attestation: Dict[str, Any]


@dataclass(frozen=True)
class VerifiedGatewayAttestation:
    """Gateway evidence that has passed quote, TLS, and deployment checks."""

    attestation: Dict[str, Any]
    peer_spki_fingerprint: str


def _record_failure(
    failures: List[VerificationFailure], check: str, passed: bool, detail: str
) -> None:
    if not passed:
        failures.append(VerificationFailure(check, detail))


def _raise_if_failed(failures: Sequence[VerificationFailure]) -> None:
    if not failures:
        return
    print("\n✗ Attestation verification summary")
    for failure in failures:
        print(f"  - {failure.check}: {failure.detail}")
    raise AttestationVerificationError(failures)


async def verify_model_attestation(
    attestation: Dict[str, Any], nonce: str
) -> VerifiedModelAttestation:
    """Verify model evidence: quote -> binding -> deployment -> GPU evidence."""

    failures: List[VerificationFailure] = []
    print("\n🔐 Model attestation")
    print("Signing address:", attestation.get("signing_address"))
    print("Signing algorithm:", attestation.get("signing_algo"))
    print("Request nonce:", nonce)

    print("\n🔐 Intel TDX quote")
    quote = await verify_dstack_quote(attestation)
    quote_valid = quote is not None and quote.get("verified") is True
    _record_failure(
        failures,
        "Intel TDX quote",
        quote_valid,
        "quote did not verify with an accepted TCB status",
    )
    _record_failure(
        failures,
        "TDX debug configuration",
        quote is not None and quote.get("debug_enabled") is False,
        "quote enables debug mode or did not expose TD attributes",
    )

    print("\n🔐 Model report-data binding")
    report_data = verify_report_data_binding(attestation, nonce, quote)
    _record_failure(
        failures,
        "API report_data",
        report_data["report_data_matches_quote"],
        "Cloud API report_data does not equal report_data in the verified quote",
    )
    _record_failure(
        failures,
        "model signer report-data binding",
        report_data["binds_signer"],
        "verified quote does not bind the advertised model signer",
    )
    _record_failure(
        failures,
        "quote nonce binding",
        report_data["embeds_nonce"],
        "verified quote does not embed this verifier's nonce",
    )

    print("\n🔐 Measured deployment")
    deployment = verify_dstack_deployment(attestation, quote)
    event_log = deployment["event_log"]
    _record_failure(
        failures,
        "RTMR3 event-log replay",
        event_log["replay_matches"],
        "event log does not replay to RTMR3 from the verified quote",
    )
    compose = deployment["compose"]
    _record_failure(
        failures,
        "app_compose MRCONFIGID binding",
        compose["mrconfig_matches"],
        "app_compose is not bound to MRCONFIGID from the verified quote",
    )

    print("\n🔐 GPU evidence")
    gpu = verify_nvidia_evidence(attestation, nonce)
    _record_failure(
        failures,
        "GPU evidence",
        gpu["verified"],
        "provided NVIDIA evidence is malformed, stale, or rejected by NRAS",
    )

    _raise_if_failed(failures)
    print("\n✓ Model attestation verification passed")
    return VerifiedModelAttestation(attestation)


async def verify_gateway_attestation(
    attestation: Dict[str, Any], nonce: str, peer_spki_fingerprint: Optional[str]
) -> VerifiedGatewayAttestation:
    """Verify Gateway evidence: quote -> TLS binding -> deployment."""

    failures: List[VerificationFailure] = []
    print("\n🔐 Gateway attestation")
    print("Signing address:", attestation.get("signing_address"))
    print("Signing algorithm:", attestation.get("signing_algo"))
    print("Request nonce:", nonce)

    print("\n🔐 Intel TDX quote")
    quote = await verify_dstack_quote(attestation)
    quote_valid = quote is not None and quote.get("verified") is True
    _record_failure(
        failures,
        "Intel TDX quote",
        quote_valid,
        "quote did not verify with an accepted TCB status",
    )
    _record_failure(
        failures,
        "TDX debug configuration",
        quote is not None and quote.get("debug_enabled") is False,
        "quote enables debug mode or did not expose TD attributes",
    )

    print("\n🔐 Gateway report-data and TLS binding")
    report_data = verify_report_data_binding_with_tls_fingerprint(
        attestation,
        nonce,
        quote,
        require_advertised_report_data=True,
    )
    _record_failure(
        failures,
        "API report_data",
        report_data["report_data_matches_quote"],
        "Cloud API report_data does not equal report_data in the verified quote",
    )
    _record_failure(
        failures,
        "Gateway signer and TLS report-data binding",
        report_data["binds_signer"],
        "verified quote does not bind the advertised Gateway signer and TLS fingerprint",
    )
    _record_failure(
        failures,
        "quote nonce binding",
        report_data["embeds_nonce"],
        "verified quote does not embed this verifier's nonce",
    )

    try:
        declared = decode_hex(
            attestation.get("tls_cert_fingerprint"),
            "attestation.tls_cert_fingerprint",
        )
        observed = decode_hex(peer_spki_fingerprint, "observed TLS peer SPKI")
        peer_matches = len(declared) == 32 and declared == observed
    except (TypeError, ValueError) as error:
        peer_matches = False
        print("Observed TLS peer matches attested fingerprint:", False)
        print("  error:", error)
    else:
        print("Observed TLS peer matches attested fingerprint:", peer_matches)
        if not peer_matches:
            print("  attested:", declared.hex())
            print("  observed:", observed.hex())
    _record_failure(
        failures,
        "Gateway peer TLS binding",
        peer_matches,
        "TLS peer for the evidence request differs from the quote-bound fingerprint",
    )

    print("\n🔐 Measured deployment")
    deployment = verify_dstack_deployment(attestation, quote)
    event_log = deployment["event_log"]
    _record_failure(
        failures,
        "RTMR3 event-log replay",
        event_log["replay_matches"],
        "event log does not replay to RTMR3 from the verified quote",
    )
    compose = deployment["compose"]
    _record_failure(
        failures,
        "app_compose MRCONFIGID binding",
        compose["mrconfig_matches"],
        "app_compose is not bound to MRCONFIGID from the verified quote",
    )

    _raise_if_failed(failures)
    if peer_spki_fingerprint is None:
        raise RuntimeError("Gateway peer TLS fingerprint is missing")
    print("\n✓ Gateway attestation verification passed")
    return VerifiedGatewayAttestation(attestation, peer_spki_fingerprint)
