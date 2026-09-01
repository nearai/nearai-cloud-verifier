#!/usr/bin/env python3
"""Shared dstack quote, binding, deployment, and GPU primitives.

Endpoint-specific Gateway and direct-endpoint flows live outside this module.
Keeping those flows separate makes their different verification goals explicit.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from hashlib import sha256, sha384
from typing import Any, Dict, List, Optional, Sequence, Tuple

import dcap_qvl
import requests


GPU_VERIFIER_API = "https://nras.attestation.nvidia.com/v3/attest/gpu"
SIGSTORE_SEARCH_BASE = "https://search.sigstore.dev/?hash="
SUPPORTED_SIGNING_ALGOS = {"ecdsa", "ed25519"}
ACCEPTED_TCB_STATUSES = {"UpToDate", "OutOfDate"}
DSTACK_RUNTIME_EVENT_TYPE = 0x08000001


@dataclass(frozen=True)
class VerificationFailure:
    """One failed verification step, retained for the final summary."""

    check: str
    detail: str


class AttestationVerificationError(RuntimeError):
    """Raised after all independent evidence checks have been reported."""

    def __init__(self, failures: Sequence[VerificationFailure]):
        self.failures = tuple(failures)
        summary = "; ".join(f"{failure.check}: {failure.detail}" for failure in failures)
        super().__init__(f"Attestation verification failed ({summary})")


def decode_hex(value: object, label: str) -> bytes:
    """Decode one non-empty hexadecimal field from a public API response."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be hexadecimal text")
    normalized = value[2:] if value[:2].lower() == "0x" else value
    if (
        not normalized
        or len(normalized) % 2
        or re.fullmatch(r"[0-9a-fA-F]+", normalized) is None
    ):
        raise ValueError(f"{label} must contain an even number of hexadecimal characters")
    return bytes.fromhex(normalized)


def signing_identity(value: Dict[str, Any], label: str) -> Tuple[str, bytes]:
    """Return a normalized signing algorithm and signer bytes."""

    signing_algo = value.get("signing_algo")
    if not isinstance(signing_algo, str) or signing_algo not in SUPPORTED_SIGNING_ALGOS:
        raise ValueError(f"{label}.signing_algo must be 'ecdsa' or 'ed25519'")
    address = decode_hex(value.get("signing_address"), f"{label}.signing_address")
    expected_length = 20 if signing_algo == "ecdsa" else 32
    if len(address) != expected_length:
        raise ValueError(
            f"{label}.signing_address must be {expected_length} bytes for {signing_algo}"
        )
    return signing_algo, address


def signing_identities_match(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Compare signing identities by decoded bytes, not their hex spelling."""

    return signing_identity(left, "left") == signing_identity(right, "right")


def fetch_nvidia_verification(payload: Dict[str, Any]) -> Any:
    """Submit GPU evidence to NVIDIA NRAS for verification."""

    response = requests.post(GPU_VERIFIER_API, json=payload, timeout=30)
    response.raise_for_status()
    return response.json()


def base64url_decode_jwt_payload(jwt_token: str) -> Dict[str, Any]:
    """Decode a JWT payload for the documented NRAS result claim."""

    parts = jwt_token.split(".")
    if len(parts) != 3:
        raise ValueError("NRAS JWT must contain three dot-separated sections")
    payload_b64 = parts[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    value = json.loads(base64.urlsafe_b64decode(padded))
    if not isinstance(value, dict):
        raise ValueError("NRAS JWT payload is not a JSON object")
    return value


def _quote_field_bytes(intel_result: Dict[str, Any], field: str) -> bytes:
    value = intel_result["quote"]["body"][field]
    return decode_hex(value, f"verified quote {field}")


def _report_data_bytes(intel_result: Dict[str, Any]) -> bytes:
    """Return report-data bytes extracted from the verified quote."""

    return _quote_field_bytes(intel_result, "reportdata")


def verify_attestation_nonce(attestation: Dict[str, Any], request_nonce: str) -> bool:
    """Check the report's echoed request_nonce before inspecting the quote."""

    actual = attestation.get("request_nonce")
    matches = isinstance(actual, str) and actual.lower() == request_nonce.lower()
    print("Attestation request_nonce matches request nonce:", matches)
    if not matches:
        print("  expected:", request_nonce)
        print("  actual:  ", actual)
    return matches


def _check_report_data(
    attestation: Dict[str, Any],
    request_nonce: str,
    intel_result: Optional[Dict[str, Any]],
    *,
    require_tls_fingerprint: bool = False,
    require_advertised_report_data: bool = False,
) -> Dict[str, bool]:
    """Verify quote report-data, signer/TLS, and nonce bindings."""

    failed = {
        "report_data_matches_quote": False,
        "binds_signer": False,
        "embeds_nonce": False,
    }
    if intel_result is None:
        print("Cannot check report data: Intel quote verification did not produce a quote.")
        return failed

    try:
        report_data = _report_data_bytes(intel_result)
    except (KeyError, TypeError, ValueError) as error:
        print("Could not decode verified quote report data:", error)
        return failed
    if len(report_data) != 64:
        print("Verified quote report data is 64 bytes:", False)
        print("  actual bytes:", len(report_data))
        return failed

    advertised = attestation.get("report_data")
    if advertised is None:
        # This JSON field is a convenience copy. The verified quote is the
        # source of truth, and direct endpoints need not expose the copy.
        advertised_matches = not require_advertised_report_data
        print("JSON report_data is present:", False)
        if advertised_matches:
            print("Using report_data from the verified quote directly.")
        else:
            print("Cloud API Gateway evidence must include report_data.")
    else:
        try:
            advertised_bytes = decode_hex(advertised, "attestation.report_data")
            advertised_matches = len(advertised_bytes) == 64 and advertised_bytes == report_data
        except ValueError as error:
            advertised_matches = False
            print("Could not decode attestation.report_data:", error)
        print("JSON report_data matches verified quote:", advertised_matches)
        if not advertised_matches:
            if isinstance(advertised, str):
                print("  JSON value:  ", advertised.removeprefix("0x"))
            print("  quote value: ", report_data.hex())

    try:
        signing_algo, signing_address = signing_identity(attestation, "attestation")
        fingerprint_value = attestation.get("tls_cert_fingerprint")
        if require_tls_fingerprint:
            if fingerprint_value is None:
                raise ValueError("Gateway attestation is missing tls_cert_fingerprint")
            fingerprint = decode_hex(
                fingerprint_value, "attestation.tls_cert_fingerprint"
            )
            if len(fingerprint) != 32:
                raise ValueError("attestation.tls_cert_fingerprint must be 32 bytes")
            expected_first32 = sha256(signing_address + fingerprint).digest()
            binding_label = "Report data binds signing address + TLS fingerprint"
        else:
            if fingerprint_value is not None:
                raise ValueError(
                    "Attestation includes tls_cert_fingerprint; use TLS report-data binding"
                )
            expected_first32 = signing_address.ljust(32, b"\x00")
            binding_label = "Report data binds signing address"
        binds_signer = report_data[:32] == expected_first32
        print("Signing algorithm:", signing_algo)
        print(f"{binding_label}:", binds_signer)
        if not binds_signer:
            print("  expected:", expected_first32.hex())
            print("  actual:  ", report_data[:32].hex())
    except ValueError as error:
        binds_signer = False
        print("Could not verify signer/TLS report-data binding:", error)

    try:
        raw_nonce = decode_hex(request_nonce, "request nonce")
        nonce_matches = len(raw_nonce) == 32 and report_data[32:64] == raw_nonce
    except ValueError as error:
        nonce_matches = False
        print("Could not decode request nonce:", error)
    print("Report data embeds request nonce:", nonce_matches)
    if not nonce_matches:
        print("  expected:", request_nonce)
        print("  actual:  ", report_data[32:64].hex())

    return {
        "report_data_matches_quote": advertised_matches,
        "binds_signer": binds_signer,
        "embeds_nonce": nonce_matches,
    }


def verify_report_data_binding(
    attestation: Dict[str, Any],
    request_nonce: str,
    intel_result: Optional[Dict[str, Any]],
) -> Dict[str, bool]:
    """Verify signer and nonce report-data binding without TLS evidence."""

    return _check_report_data(attestation, request_nonce, intel_result)


def verify_report_data_binding_with_tls_fingerprint(
    attestation: Dict[str, Any],
    request_nonce: str,
    intel_result: Optional[Dict[str, Any]],
    *,
    require_advertised_report_data: bool = False,
) -> Dict[str, bool]:
    """Verify signer, TLS fingerprint, and nonce binding from the quote.

    Direct model reports may omit the JSON ``report_data`` convenience copy,
    while Cloud API Gateway reports are expected to include it.
    """

    return _check_report_data(
        attestation,
        request_nonce,
        intel_result,
        require_tls_fingerprint=True,
        require_advertised_report_data=require_advertised_report_data,
    )


def verify_nvidia_evidence(attestation: Dict[str, Any], request_nonce: str) -> Dict[str, Any]:
    """Verify optional NVIDIA evidence and bind it to the client nonce."""

    raw_payload = attestation.get("nvidia_payload")
    if raw_payload is None or raw_payload == "":
        print("GPU evidence: not provided (accepted by the default if-present policy).")
        return {"provided": False, "verified": True}
    if not isinstance(raw_payload, str):
        print("GPU evidence payload is valid JSON:", False)
        return {"provided": True, "verified": False}

    try:
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict) or not isinstance(payload.get("nonce"), str):
            raise ValueError("payload must contain a string nonce")
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        print("GPU evidence payload is valid JSON:", False)
        print("  error:", error)
        return {"provided": True, "verified": False}

    nonce_matches = payload["nonce"].lower() == request_nonce.lower()
    print("GPU payload nonce matches request nonce:", nonce_matches)
    if not nonce_matches:
        print("  expected:", request_nonce)
        print("  actual:  ", payload["nonce"])

    try:
        body = fetch_nvidia_verification(payload)
        if (
            not isinstance(body, list)
            or not body
            or not isinstance(body[0], list)
            or len(body[0]) < 2
            or body[0][0] != "JWT"
            or not isinstance(body[0][1], str)
        ):
            raise ValueError("NRAS did not return a JWT as its first result")
        verdict = base64url_decode_jwt_payload(body[0][1]).get(
            "x-nvidia-overall-att-result"
        )
        verdict_matches = verdict is True or verdict == "PASS"
        print("NVIDIA attestation verdict:", verdict)
        if not verdict_matches:
            print("  expected: True")
        return {
            "provided": True,
            "nonce_matches": nonce_matches,
            "verdict": verdict,
            "verified": nonce_matches and verdict_matches,
        }
    except (requests.RequestException, ValueError, KeyError, TypeError) as error:
        print("NVIDIA GPU evidence verification failed:", error)
        return {"provided": True, "nonce_matches": nonce_matches, "verified": False}


def _td10_result(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("DCAP result is not a JSON object")
    report = raw.get("report")
    if not isinstance(report, dict):
        raise ValueError("DCAP result has no report object")
    td10 = report.get("TD10")
    if isinstance(td10, dict):
        return td10
    td15 = report.get("TD15")
    if isinstance(td15, dict) and isinstance(td15.get("base"), dict):
        return td15["base"]
    raise ValueError("DCAP result is not a TD10 or TD15 quote")


def _quote_hex(value: Any, label: str) -> str:
    if isinstance(value, str):
        return decode_hex(value, label).hex()
    if isinstance(value, list) and all(
        isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255
        for item in value
    ):
        return bytes(value).hex()
    raise ValueError(f"{label} is not a byte sequence")


async def verify_dstack_quote(attestation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Verify an Intel TDX quote and retain the measurements used below."""

    try:
        intel_quote = decode_hex(attestation.get("intel_quote"), "attestation.intel_quote")
        result = await dcap_qvl.get_collateral_and_verify(intel_quote)
        raw_result = json.loads(result.to_json())
        print("TDX quote verification result:", json.dumps(raw_result, indent=2))

        td10 = _td10_result(raw_result)
        report_data = _quote_hex(td10.get("report_data"), "quote.report_data")
        mr_config = _quote_hex(td10.get("mr_config_id"), "quote.mr_config_id")
        rtmr3 = _quote_hex(td10.get("rt_mr3"), "quote.rt_mr3")
        attributes = _quote_hex(td10.get("td_attributes"), "quote.td_attributes")
        attributes_bytes = decode_hex(attributes, "quote.td_attributes")
        status = getattr(result, "status", None)
        advisory_ids = list(getattr(result, "advisory_ids", []))
        if not isinstance(status, str):
            raise ValueError("DCAP result has no TCB status")
        if not all(isinstance(advisory, str) for advisory in advisory_ids):
            raise ValueError("DCAP result has malformed advisory IDs")
    except Exception as error:
        print("TDX quote verification failed:", error)
        return None

    verified = status in ACCEPTED_TCB_STATUSES
    debug_enabled = bool(attributes_bytes and attributes_bytes[0] & 0x01)
    print("TDX quote status:", status)
    print("Intel TDX quote verified:", verified)
    print("TDX debug bit disabled:", not debug_enabled)
    if status == "OutOfDate":
        print("Intel TDX quote status OutOfDate is accepted by the default policy.")

    return {
        "quote": {
            "body": {
                "reportdata": report_data,
                "mrconfig": mr_config,
                "rtmr3": rtmr3,
                "attributes": attributes,
            }
        },
        "verified": verified,
        "status": status,
        "advisory_ids": advisory_ids,
        "debug_enabled": debug_enabled,
    }


def _event_digest(entry: Dict[str, Any], index: int) -> Tuple[bytes, Optional[Tuple[str, str]]]:
    label = f"event_log[{index}]"
    event_type = entry.get("event_type", 0)
    imr = entry.get("imr")
    if (
        not isinstance(event_type, int)
        or isinstance(event_type, bool)
        or not isinstance(imr, int)
        or isinstance(imr, bool)
    ):
        raise ValueError(f"{label} has non-integer event_type or imr")
    digest = entry.get("digest")
    if not isinstance(digest, str):
        raise ValueError(f"{label}.digest must be hexadecimal text")

    runtime_measurement = None
    if event_type == DSTACK_RUNTIME_EVENT_TYPE:
        event = entry.get("event", "")
        event_payload = entry.get("event_payload", "")
        if not isinstance(event, str) or not isinstance(event_payload, str):
            raise ValueError(f"{label} has a non-string runtime event")
        payload = decode_hex(event_payload, f"{label}.event_payload") if event_payload else b""
        computed = sha384(
            DSTACK_RUNTIME_EVENT_TYPE.to_bytes(4, "little")
            + b":"
            + event.encode("utf-8")
            + b":"
            + payload
        ).digest()
        if digest:
            stored = decode_hex(digest, f"{label}.digest")
            if len(stored) != 48 or stored != computed:
                raise ValueError(f"{label}.digest does not match its runtime event")
        if event in {"os-image-hash", "compose-hash"}:
            runtime_measurement = (event, event_payload)
        return computed, runtime_measurement

    stored = decode_hex(digest, f"{label}.digest")
    if len(stored) != 48:
        raise ValueError(f"{label}.digest must be 48 bytes")
    return stored, runtime_measurement


def check_event_log(
    attestation: Dict[str, Any], intel_result: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Replay RTMR3 from the dstack event log and compare it with the quote."""

    if intel_result is None:
        print("Cannot replay RTMR3: Intel quote verification did not produce a quote.")
        return {"replay_matches": False}
    try:
        raw_events = attestation.get("event_log")
        events = json.loads(raw_events) if isinstance(raw_events, str) else raw_events
        if not isinstance(events, list):
            raise ValueError("event_log must be a JSON array")
        expected_rtmr3 = _quote_field_bytes(intel_result, "rtmr3")
        if len(expected_rtmr3) != 48:
            raise ValueError("quoted RTMR3 must be 48 bytes")

        replayed = bytes(48)
        count = 0
        measurements: Dict[str, str] = {}
        for index, entry in enumerate(events):
            if not isinstance(entry, dict):
                raise ValueError(f"event_log[{index}] must be an object")
            if entry.get("imr") != 3:
                continue
            digest, measurement = _event_digest(entry, index)
            replayed = sha384(replayed + digest).digest()
            count += 1
            if measurement is not None:
                measurements[measurement[0]] = measurement[1]
        matches = count > 0 and replayed == expected_rtmr3
        print("RTMR3 replay has runtime events:", count > 0)
        print("RTMR3 replay matches verified quote:", matches)
        if not matches:
            print("  expected:", expected_rtmr3.hex())
            print("  actual:  ", replayed.hex())
        if measurements:
            print("Runtime measurements:", json.dumps(measurements, indent=2))
        return {
            "replay_matches": matches,
            "event_count": count,
            "measurements": measurements,
        }
    except (TypeError, ValueError, json.JSONDecodeError, KeyError) as error:
        print("RTMR3 event-log verification failed:", error)
        return {"replay_matches": False}


def extract_sigstore_links(compose: str) -> List[str]:
    """Extract image digests for optional, human-facing Sigstore lookup links."""

    digests = re.findall(r"@sha256:([0-9a-f]{64})", compose)
    return [
        f"{SIGSTORE_SEARCH_BASE}sha256:{digest}"
        for index, digest in enumerate(digests)
        if digest not in digests[:index]
    ]


def _parsed_tcb_info(attestation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    raw_info = attestation.get("info")
    if not isinstance(raw_info, dict):
        return None
    tcb_info = raw_info.get("tcb_info")
    if isinstance(tcb_info, str):
        try:
            tcb_info = json.loads(tcb_info)
        except json.JSONDecodeError:
            return None
    return tcb_info if isinstance(tcb_info, dict) else None


def show_image_digest_lookup_links(attestation: Dict[str, Any]) -> None:
    """Display optional image-digest lookup links without treating them as proof."""

    tcb_info = _parsed_tcb_info(attestation) or {}
    compose = tcb_info.get("app_compose")
    if not isinstance(compose, str):
        return
    links = extract_sigstore_links(compose)
    if not links:
        return
    print("\nImage digest lookup links (diagnostic only; not provenance verification):")
    for link in links:
        print(f"  {link}")


def check_app_compose_measurement(
    attestation: Dict[str, Any], intel_result: Optional[Dict[str, Any]]
) -> Dict[str, bool]:
    """Display the measured compose manifest and verify its MRCONFIGID binding."""

    tcb_info = _parsed_tcb_info(attestation)
    app_compose = tcb_info.get("app_compose") if tcb_info is not None else None
    if not isinstance(app_compose, str):
        print("Compose measurement is present:", False)
        return {"mrconfig_matches": False}
    print("\nDocker compose manifest measured by the enclave:")
    try:
        compose_document = json.loads(app_compose)
        docker_compose = compose_document.get("docker_compose_file")
        print(docker_compose if isinstance(docker_compose, str) else app_compose)
    except json.JSONDecodeError:
        print(app_compose)

    compose_hash = sha256(app_compose.encode("utf-8")).digest()
    print("Compose sha256:", compose_hash.hex())
    if intel_result is None:
        print("MRCONFIGID binds compose hash:", False)
        return {"mrconfig_matches": False}
    try:
        mr_config = _quote_field_bytes(intel_result, "mrconfig")
        version_matches = len(mr_config) >= 33 and mr_config[0] == 1
        hash_matches = version_matches and mr_config[1:33] == compose_hash
        print("MRCONFIGID (from verified quote):", mr_config.hex())
        print("MRCONFIGID version is supported:", version_matches)
        print("MRCONFIGID binds compose hash:", hash_matches)
        return {"mrconfig_matches": version_matches and hash_matches}
    except (KeyError, TypeError, ValueError) as error:
        print("Could not verify MRCONFIGID compose binding:", error)
        return {"mrconfig_matches": False}


def verify_dstack_deployment(
    attestation: Dict[str, Any], intel_result: Optional[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    """Verify the event-log replay and compose measurement of a dstack deployment."""

    deployment = {
        "event_log": check_event_log(attestation, intel_result),
        "compose": check_app_compose_measurement(attestation, intel_result),
    }
    show_image_digest_lookup_links(attestation)
    return deployment
