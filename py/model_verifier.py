#!/usr/bin/env python3
"""An independent, print-oriented verifier for NEAR AI Cloud evidence.

This file intentionally does not depend on the SDK. It shows the public Cloud
API requests and each cryptographic binding in a form that can be read, copied,
or ported to another language.

It distinguishes two evidence paths:

* model evidence is requested for a model and a signature's model signer;
* Gateway evidence is requested separately and binds the Gateway TLS peer.

The individual checks print their result so a failed report remains useful for
diagnosis. ``verify_attestation`` collects those failures and raises at the
end, rather than reporting success after a failed check.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import re
import secrets
import ssl
from dataclasses import dataclass
from hashlib import sha256, sha384
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urlsplit

import dcap_qvl
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization


BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")
API_KEY = os.environ.get("API_KEY", "")

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


def _cloud_api_url(path: str) -> str:
    """Return one Cloud API URL while accepting a BASE_URL ending in /v1."""

    base = BASE_URL.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/{path.lstrip('/')}"
    return f"{base}/v1/{path.lstrip('/')}"


def _authorization_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    headers = {} if extra is None else dict(extra)
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    return headers


def _request_json(
    path: str,
    params: Dict[str, str],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Fetch one JSON Cloud API response and reject non-object envelopes."""

    response = requests.get(
        _cloud_api_url(path),
        params=params,
        headers=_authorization_headers(headers),
        timeout=30,
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError(f"{path} returned {type(value).__name__}, expected a JSON object")
    return value


def fetch_model_attestations(
    model: str,
    signing_algo: Optional[str] = None,
    signing_address: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Fetch NEAR model evidence with a fresh nonce and no TLS binding.

    ``provider=near`` scopes this public model-evidence path to NEAR's own
    model fleet. ``x-no-aliasing`` rejects aliases rather than resolving them,
    so callers must supply the canonical model ID used in the completion.
    """

    nonce = secrets.token_hex(32)
    params = {
        "model": model,
        "provider": "near",
        "nonce": nonce,
        "include_tls_fingerprint": "false",
    }
    if signing_algo is not None:
        params["signing_algo"] = signing_algo
    if signing_address is not None:
        params["signing_address"] = signing_address
    report = _request_json(
        "attestation/report",
        params,
        headers={"x-no-aliasing": "true"},
    )
    attestations = report.get("model_attestations")
    if not isinstance(attestations, list) or not all(
        isinstance(attestation, dict) for attestation in attestations
    ):
        raise ValueError("Cloud API model report does not contain model_attestations[]")
    return attestations, nonce


def _peer_spki_fingerprint(certificate_der: bytes) -> str:
    """SHA-256 of the TLS certificate's SubjectPublicKeyInfo DER bytes."""

    certificate = x509.load_der_x509_certificate(certificate_der)
    spki_der = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).hexdigest()


def _fetch_gateway_report_with_peer_spki(
    params: Dict[str, str]
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch Gateway evidence and retain the TLS peer from that same request.

    ``requests`` hides the connection after a response is read. The
    standard-library HTTPS connection keeps the certificate observable long
    enough to bind it to this exact evidence request.
    """

    url = urlsplit(_cloud_api_url("attestation/report"))
    if url.scheme != "https" or not url.hostname:
        # Local HTTP is useful for development, but cannot provide the peer
        # certificate needed for the production Gateway TLS check.
        return _request_json("attestation/report", params), None

    path = url.path or "/"
    query = urlencode(params)
    if url.query:
        query = f"{url.query}&{query}"
    if query:
        path = f"{path}?{query}"

    connection = http.client.HTTPSConnection(
        url.hostname,
        url.port or 443,
        context=ssl.create_default_context(),
        timeout=30,
    )
    try:
        connection.connect()
        socket = connection.sock
        if socket is None:
            raise RuntimeError("HTTPS connection did not expose a TLS socket")
        certificate_der = socket.getpeercert(binary_form=True)
        if not certificate_der:
            raise RuntimeError("TLS peer did not provide a certificate")
        peer_spki = _peer_spki_fingerprint(certificate_der)

        connection.request("GET", path, headers=_authorization_headers())
        response = connection.getresponse()
        body = response.read()
        if not 200 <= response.status < 300:
            rendered = body.decode("utf-8", "replace")
            raise RuntimeError(f"Cloud API returned HTTP {response.status}: {rendered}")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("attestation/report returned a non-object JSON value")
        return value, peer_spki
    finally:
        connection.close()


def fetch_gateway_attestation(
    signing_algo: Optional[str] = None,
) -> Tuple[Dict[str, Any], str, Optional[str]]:
    """Fetch standalone Gateway evidence and its observed TLS peer SPKI.

    Gateway evidence is selected by its signing algorithm only. No model,
    provider, or ``signing_address`` query parameter is sent here: those select
    model evidence, not a Gateway identity.
    """

    nonce = secrets.token_hex(32)
    params = {"nonce": nonce, "include_tls_fingerprint": "true"}
    if signing_algo is not None:
        params["signing_algo"] = signing_algo
    report, peer_spki = _fetch_gateway_report_with_peer_spki(params)
    attestation = report.get("gateway_attestation")
    if not isinstance(attestation, dict):
        raise ValueError("Cloud API Gateway report does not contain gateway_attestation")
    return attestation, nonce, peer_spki


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


def fetch_model_attestation_for_signature(
    model: str,
    signature: Dict[str, Any],
) -> Tuple[Dict[str, Any], str]:
    """Fetch exactly one model attestation for a ``provider_tee`` signature."""

    if signature.get("signature_kind") != "provider_tee":
        raise ValueError("Model evidence can only verify a provider_tee signature")
    signing_algo, _ = signing_identity(signature, "signature")
    signing_address = signature["signing_address"]
    attestations, nonce = fetch_model_attestations(
        model,
        signing_algo=signing_algo,
        # Preserve the signature's public spelling (including ECDSA's 0x
        # prefix) when it is forwarded to the Cloud API model selector.
        signing_address=signing_address,
    )
    matches = [
        attestation
        for attestation in attestations
        if signing_identities_match(attestation, signature)
    ]
    if len(matches) != 1:
        raise ValueError(
            "Cloud API must return exactly one model attestation matching the signature signer; "
            f"received {len(matches)} matching entries"
        )
    return matches[0], nonce


def fetch_gateway_attestation_for_signature(
    signature: Dict[str, Any],
) -> Tuple[Dict[str, Any], str, Optional[str]]:
    """Fetch Gateway evidence for a ``gateway`` signature and bind its signer."""

    if signature.get("signature_kind") != "gateway":
        raise ValueError("Gateway evidence can only verify a gateway signature")
    signing_algo, _ = signing_identity(signature, "signature")
    attestation, nonce, peer_spki = fetch_gateway_attestation(signing_algo=signing_algo)
    if not signing_identities_match(attestation, signature):
        raise ValueError("Gateway attestation signer does not match the response signature signer")
    return attestation, nonce, peer_spki


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


def check_reported_nonce(attestation: Dict[str, Any], request_nonce: str) -> bool:
    """Check Cloud API's echoed request_nonce before inspecting the quote."""

    actual = attestation.get("request_nonce")
    matches = isinstance(actual, str) and actual.lower() == request_nonce.lower()
    print("Attestation request_nonce matches request nonce:", matches)
    if not matches:
        print("  expected:", request_nonce)
        print("  actual:  ", actual)
    return matches


def check_report_data(
    attestation: Dict[str, Any],
    request_nonce: str,
    intel_result: Optional[Dict[str, Any]],
    *,
    require_tls_fingerprint: bool = False,
    require_advertised_report_data: bool = False,
) -> Dict[str, bool]:
    """Verify API and quote report-data, signer/TLS, and nonce bindings."""

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

    if "report_data" not in attestation:
        # Model provider reports may omit this convenience copy. The verified
        # quote is still the source of truth; Gateway reports requested with
        # include_tls_fingerprint=true must expose it.
        advertised_matches = not require_advertised_report_data
        print("API report_data is present:", False)
        if require_advertised_report_data:
            print("API report_data matches verified quote:", False)
    else:
        advertised = attestation["report_data"]
        try:
            advertised_bytes = decode_hex(advertised, "attestation.report_data")
            advertised_matches = len(advertised_bytes) == 64 and advertised_bytes == report_data
        except ValueError as error:
            advertised_matches = False
            print("Could not decode attestation.report_data:", error)
        print("API report_data matches verified quote:", advertised_matches)
        if not advertised_matches:
            if isinstance(advertised, str):
                print("  API value:   ", advertised.removeprefix("0x"))
            print("  quote value: ", report_data.hex())

    try:
        signing_algo, signing_address = signing_identity(attestation, "attestation")
        fingerprint_value = attestation.get("tls_cert_fingerprint")
        if fingerprint_value is None:
            if require_tls_fingerprint:
                raise ValueError("Gateway attestation is missing tls_cert_fingerprint")
            expected_first32 = signing_address.ljust(32, b"\x00")
            binding_label = "Report data binds signing address"
        else:
            fingerprint = decode_hex(
                fingerprint_value, "attestation.tls_cert_fingerprint"
            )
            if len(fingerprint) != 32:
                raise ValueError("attestation.tls_cert_fingerprint must be 32 bytes")
            expected_first32 = sha256(signing_address + fingerprint).digest()
            binding_label = "Report data binds signing address + TLS fingerprint"
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


def check_gpu(attestation: Dict[str, Any], request_nonce: str) -> Dict[str, Any]:
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


async def check_tdx_quote(attestation: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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


def _record_failure(
    failures: List[VerificationFailure], check: str, passed: bool, detail: str
) -> None:
    if not passed:
        failures.append(VerificationFailure(check, detail))


async def verify_attestation(
    attestation: Dict[str, Any],
    request_nonce: str,
    verify_model: bool = False,
    *,
    require_peer_tls_binding: bool = False,
    peer_spki_fingerprint: Optional[str] = None,
    expected_signer: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run all applicable checks, then fail if any security check failed."""

    failures: List[VerificationFailure] = []
    print("\n🔐 Attestation")
    print("Request nonce:", request_nonce)
    if isinstance(attestation.get("signing_address"), str):
        print("Signing address:", attestation["signing_address"])

    _record_failure(
        failures,
        "attestation request nonce",
        check_reported_nonce(attestation, request_nonce),
        "Cloud API request_nonce differs from the nonce sent by this verifier",
    )

    print("\n🔐 Intel TDX quote")
    intel_result = await check_tdx_quote(attestation)
    quote_valid = intel_result is not None and intel_result.get("verified") is True
    _record_failure(
        failures,
        "Intel TDX quote",
        quote_valid,
        "quote did not verify with an accepted TCB status",
    )
    debug_disabled = intel_result is not None and intel_result.get("debug_enabled") is False
    _record_failure(
        failures,
        "TDX debug configuration",
        debug_disabled,
        "quote enables debug mode or did not expose TD attributes",
    )

    print("\n🔐 TDX report data")
    report_data = check_report_data(
        attestation,
        request_nonce,
        intel_result,
        require_tls_fingerprint=require_peer_tls_binding,
        require_advertised_report_data=require_peer_tls_binding,
    )
    _record_failure(
        failures,
        "API report_data",
        report_data["report_data_matches_quote"],
        "Cloud API report_data does not equal report_data in the verified quote",
    )
    _record_failure(
        failures,
        "signer report-data binding",
        report_data["binds_signer"],
        "verified quote does not bind the advertised signer and TLS fingerprint",
    )
    _record_failure(
        failures,
        "quote nonce binding",
        report_data["embeds_nonce"],
        "verified quote does not embed this verifier's nonce",
    )

    print("\n🔐 RTMR3 event log")
    event_log = check_event_log(attestation, intel_result)
    _record_failure(
        failures,
        "RTMR3 event-log replay",
        event_log["replay_matches"],
        "event log does not replay to RTMR3 from the verified quote",
    )

    print("\n🔐 Compose measurement")
    compose = check_app_compose_measurement(attestation, intel_result)
    _record_failure(
        failures,
        "app_compose MRCONFIGID binding",
        compose["mrconfig_matches"],
        "app_compose is not bound to MRCONFIGID from the verified quote",
    )

    if expected_signer is not None:
        try:
            signer_matches = signing_identities_match(attestation, expected_signer)
        except ValueError as error:
            signer_matches = False
            print("Attestation signer matches response signer:", False)
            print("  error:", error)
        else:
            print("Attestation signer matches response signer:", signer_matches)
        _record_failure(
            failures,
            "response signer binding",
            signer_matches,
            "attestation signing identity differs from the response signature",
        )

    if require_peer_tls_binding:
        try:
            declared = decode_hex(
                attestation.get("tls_cert_fingerprint"),
                "attestation.tls_cert_fingerprint",
            )
            peer = decode_hex(peer_spki_fingerprint, "observed TLS peer SPKI")
            peer_matches = len(declared) == 32 and declared == peer
        except ValueError as error:
            peer_matches = False
            print("Observed TLS peer matches attested fingerprint:", False)
            print("  error:", error)
        else:
            print("Observed TLS peer matches attested fingerprint:", peer_matches)
            if not peer_matches:
                print("  attested:", declared.hex())
                print("  observed:", peer.hex())
        _record_failure(
            failures,
            "Gateway peer TLS binding",
            peer_matches,
            "TLS peer for the evidence request differs from the quote-bound fingerprint",
        )

    if verify_model:
        print("\n🔐 GPU attestation")
        gpu = check_gpu(attestation, request_nonce)
        _record_failure(
            failures,
            "GPU evidence",
            gpu["verified"],
            "provided NVIDIA evidence is malformed, stale, or rejected by NRAS",
        )

    try:
        show_image_digest_lookup_links(attestation)
    except Exception as error:
        # Image lookup is a diagnostic convenience, not a substitute for the
        # quote/measurement verification chain above.
        print("Image digest lookup failed (diagnostic only):", error)

    if failures:
        print("\n✗ Attestation verification summary")
        for failure in failures:
            print(f"  - {failure.check}: {failure.detail}")
        raise AttestationVerificationError(failures)
    print("\n✓ Attestation verification passed")
    return intel_result


async def verify_gateway_tls_binding(
    signing_algo: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch Gateway evidence plus the peer TLS binding for that request.

    Gateway evidence is selected only by signing algorithm. Its signer is
    discovered from the verified evidence; callers do not supply a model or a
    signing address to this endpoint.
    """

    attestation, nonce, peer_spki = fetch_gateway_attestation(signing_algo=signing_algo)
    print("========================================")
    print("🔐 Gateway attestation")
    print("========================================")
    return await verify_attestation(
        attestation,
        nonce,
        require_peer_tls_binding=True,
        peer_spki_fingerprint=peer_spki,
    )


async def main() -> int:
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud TEE evidence")
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument(
        "--signing-algo",
        choices=sorted(SUPPORTED_SIGNING_ALGOS),
        help="Request a specific algorithm; omit to use the Cloud API default.",
    )
    args = parser.parse_args()

    failures: List[VerificationFailure] = []

    print("========================================")
    print("🔐 Gateway attestation")
    print("========================================")
    try:
        gateway, gateway_nonce, peer_spki = fetch_gateway_attestation(args.signing_algo)
        await verify_attestation(
            gateway,
            gateway_nonce,
            require_peer_tls_binding=True,
            peer_spki_fingerprint=peer_spki,
        )
    except (AttestationVerificationError, requests.RequestException, ValueError, RuntimeError) as error:
        print("Gateway verification failed:", error)
        failures.append(VerificationFailure("Gateway attestation", str(error)))

    print("\n========================================")
    print("🔐 Model attestations")
    print("========================================")
    try:
        model_attestations, model_nonce = fetch_model_attestations(
            args.model, signing_algo=args.signing_algo
        )
        if not model_attestations:
            raise ValueError("Cloud API returned no model attestations")
        for index, model_attestation in enumerate(model_attestations, start=1):
            print(f"\n--- Model attestation #{index} ---")
            try:
                await verify_attestation(
                    model_attestation, model_nonce, verify_model=True
                )
            except AttestationVerificationError as error:
                failures.append(
                    VerificationFailure(f"model attestation #{index}", str(error))
                )
    except (requests.RequestException, ValueError, RuntimeError) as error:
        print("Model evidence fetch or verification failed:", error)
        failures.append(VerificationFailure("model attestations", str(error)))

    if failures:
        print("\n✗ Overall verification failed")
        for failure in failures:
            print(f"  - {failure.check}: {failure.detail}")
        return 1
    print("\n✓ All requested attestations passed")
    return 0


if __name__ == "__main__":
    import asyncio

    raise SystemExit(asyncio.run(main()))
