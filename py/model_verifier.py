#!/usr/bin/env python3
"""Straightforward walkthrough for checking a NEAR AI Cloud attestation."""

import argparse
import base64
import dcap_qvl
import json
import re
import time
import os
import secrets
from hashlib import sha256

import requests

BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")
API_KEY = os.environ.get("API_KEY", "")

GPU_VERIFIER_API = "https://nras.attestation.nvidia.com/v3/attest/gpu"
SIGSTORE_SEARCH_BASE = "https://search.sigstore.dev/?hash="


def fetch_report(model, nonce, signing_algo="ecdsa", include_tls=False, signing_address=None):
    """Fetch attestation report from the API.

    Args:
        include_tls: if True, appends include_tls_fingerprint=true (response includes tls_cert_fingerprint in gateway_attestation and tls_certificate)
        signing_address: optional; narrows gateway quote to this signer
    """
    url = f"{BASE_URL}/v1/attestation/report?model={model}&nonce={nonce}&signing_algo={signing_algo}"
    if include_tls:
        url += "&include_tls_fingerprint=true"
    if signing_address:
        url += f"&signing_address={signing_address}"
    return requests.get(url, timeout=30).json()

def fetch_nvidia_verification(payload):
    """Submit GPU evidence to NVIDIA NRAS for verification."""
    return requests.post(GPU_VERIFIER_API, json=payload, timeout=30).json()


def base64url_decode_jwt_payload(jwt_token):
    """Decode the payload section of a JWT token."""
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode()


def _report_data_bytes(intel_result):
    """report_data from intel quote body (hex string → bytes)."""
    return bytes.fromhex(intel_result["quote"]["body"]["reportdata"].removeprefix("0x"))


def _signing_address_padded32(signing_address, signing_algo):
    """Signing address as 32 bytes (right-padded), per algo."""
    algo = signing_algo.lower()
    addr_hex = signing_address.removeprefix("0x") if algo == "ecdsa" else signing_address
    raw = bytes.fromhex(addr_hex)
    if len(raw) > 32:
        raise ValueError(
            f"Signing address is too long: expected at most 32 bytes, got {len(raw)}"
        )
    return raw.ljust(32, b"\x00")


def check_compose_manager_actions(report):
    """Verify compose-manager actions_hash matches SHA-256 of canonicalized actions.

    Canonicalization: json.dumps(actions, sort_keys=True, separators=(",", ":"))
    Then: sha256(canonical.encode("utf-8")).hexdigest() == actions_hash
    And:  actions_hash == report_data[:32].hex() (if report_data available).
    """
    cm = report.get("compose_manager_attestation")
    if not cm:
        return

    print("\n🔐 Compose-manager actions hash")

    if isinstance(cm, str):
        cm = json.loads(cm)

    actions = cm.get("actions")
    actions_hash = cm.get("actions_hash")

    if actions is None or actions_hash is None:
        print("  compose_manager_attestation present but missing actions/actions_hash — skipping")
        return

    canonical = json.dumps(actions, sort_keys=True, separators=(",", ":"))
    computed = sha256(canonical.encode("utf-8")).hexdigest()

    matches = computed == actions_hash
    print("  actions_hash matches SHA-256(canonicalize(actions)):", matches)
    if not matches:
        print("    expected:", computed)
        print("    actual:  ", actions_hash)

    # Cross-check against compose-manager's TDX report_data if available
    cm_report_data = cm.get("report_data")
    if cm_report_data:
        report_data_bytes = bytes.fromhex(cm_report_data.removeprefix("0x"))
        rd_actions_hash = report_data_bytes[:32].hex()
        binds_report_data = rd_actions_hash == actions_hash
        print("  actions_hash matches compose-manager report_data[:32]:", binds_report_data)
        if not binds_report_data:
            print("    expected:", rd_actions_hash)
            print("    actual:  ", actions_hash)

    return {"actions_hash_valid": matches}


def check_report_data(attestation, request_nonce, intel_result):
    """Verify TDX report_data binds signing address and nonce.

    When attestation contains tls_cert_fingerprint (include_tls_fingerprint mode),
    report_data[0..32] = SHA256(signing_address_bytes || fingerprint_bytes) and
    report_data[32..64] = raw nonce.
    Otherwise, report_data[0..32] = padded signing address and
    report_data[32..64] = raw nonce.

    Returns dict with binds_address and embeds_nonce.
    """
    report_data = _report_data_bytes(intel_result)
    signing_algo = attestation.get("signing_algo", "ecdsa").lower()

    embedded_first32 = report_data[:32]
    embedded_second32 = report_data[32:64] if len(report_data) >= 64 else report_data[32:]

    tls_cert_fingerprint = attestation.get("tls_cert_fingerprint")

    if tls_cert_fingerprint:
        # TLS binding mode: report_data[0..32] = SHA256(signing_address || fingerprint)
        addr_hex = attestation["signing_address"]
        if signing_algo == "ecdsa":
            signing_addr_bytes = bytes.fromhex(addr_hex.removeprefix("0x"))
        else:
            signing_addr_bytes = bytes.fromhex(addr_hex)
        fp_bytes = bytes.fromhex(tls_cert_fingerprint)
        expected_first32 = sha256(signing_addr_bytes + fp_bytes).digest()
        binds_address = embedded_first32 == expected_first32

        print("Signing algorithm:", signing_algo)
        print("Report data binds signing address + TLS fingerprint:", binds_address)
        if not binds_address:
            print("  expected:", expected_first32.hex())
            print("  actual:  ", embedded_first32.hex())
    else:
        # Standard mode: report_data[0..32] = padded signing address
        expected_address = _signing_address_padded32(attestation["signing_address"], signing_algo)
        binds_address = embedded_first32 == expected_address

        print("Signing algorithm:", signing_algo)
        print("Report data binds signing address:", binds_address)
        if not binds_address:
            print("  expected:", expected_address.hex(), "actual:", embedded_first32.hex())

    # Nonce is always raw in second 32 bytes
    try:
        raw_nonce_bytes = bytes.fromhex(request_nonce)
    except ValueError:
        raw_nonce_bytes = b""
    embeds_nonce = (
        len(raw_nonce_bytes) == 32
        and len(embedded_second32) == 32
        and embedded_second32 == raw_nonce_bytes
    )
    print("Report data embeds request nonce:", embeds_nonce)
    if not embeds_nonce:
        print("  expected:", request_nonce)
        print("  actual:  ", embedded_second32.hex())

    return {"binds_address": binds_address, "embeds_nonce": embeds_nonce}


def check_gpu(attestation, request_nonce):
    """Verify GPU attestation evidence via NVIDIA NRAS.

    Returns dict with verification results.
    """
    payload = json.loads(attestation["nvidia_payload"])

    # Verify GPU uses the same request_nonce
    nonce_matches = payload["nonce"].lower() == request_nonce.lower()
    print("GPU payload nonce matches request_nonce:", nonce_matches)

    body = fetch_nvidia_verification(payload)

    jwt_token = body[0][1]
    verdict = json.loads(base64url_decode_jwt_payload(jwt_token))["x-nvidia-overall-att-result"]
    print("NVIDIA attestation verdict:", verdict)

    return {
        "nonce_matches": nonce_matches,
        "verdict": verdict,
    }


async def check_tdx_quote(attestation):
    """Verify Intel TDX quote via dcap-qvl verification service.

    Returns the full intel_result including decoded quote data.
    """
    intel_quote = attestation["intel_quote"]

    try:
        # Convert hex string to bytes
        intel_quote_bytes = bytes.fromhex(intel_quote)
        result = await dcap_qvl.get_collateral_and_verify(intel_quote_bytes)

        print("TDX quote verification result:", result.to_json())
        result_json = json.loads(result.to_json())

        print(f"Verification successful! Status: {result.status}")
        print(f"Advisory IDs: {result.advisory_ids}")
    except ValueError as e:
        print(f"Verification failed: {e}")
        return None

    # Extract report_data and mr_config from the verification result
    report_data = ""
    mr_config = ""
    if 'report' in result_json and 'TD10' in result_json['report']:
        td10 = result_json['report']['TD10']
        report_data = td10.get('report_data', "")
        mr_config = td10.get('mr_config_id', "")

    # UpToDate is ideal; OutOfDate still has valid quote — do not fail verification
    _tdx_status_ok = frozenset({"UpToDate", "OutOfDate"})
    _status = getattr(result, "status", None)
    _verified = _status in _tdx_status_ok if _status else False
    if _status == "OutOfDate":
        # Quote still verifies; Intel marks OutOfDate when the platform TCB level
        # is below their current advisory baseline—not a cryptographic failure.
        print("Intel TDX quote status: OutOfDate")

    # Create a result structure similar to the remote verification
    intel_result = {
        "quote": {
            "body": {
                "reportdata": report_data,
                "mrconfig": mr_config
            }
        },
        "verified": _verified,
    }

    print("Intel TDX quote verified:", intel_result["verified"])
    
    return intel_result

def extract_sigstore_links(compose):
    """Extract all @sha256:xxx image digests and return Sigstore search links."""
    if not compose:
        return []

    # Match @sha256:hexdigest pattern in Docker compose
    pattern = r'@sha256:([0-9a-f]{64})'
    digests = re.findall(pattern, compose)

    # Deduplicate digests while preserving order
    seen = set()
    unique_digests = []
    for digest in digests:
        if digest not in seen:
            seen.add(digest)
            unique_digests.append(digest)

    return [f"{SIGSTORE_SEARCH_BASE}sha256:{digest}" for digest in unique_digests]


def _parsed_tcb_info(attestation):
    """Return parsed tcb_info dict or None (shared by Sigstore + compose display)."""
    raw = attestation.get("info") or {}
    tcb_info = raw.get("tcb_info") if isinstance(raw, dict) else None
    if tcb_info is None:
        return None
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
    return tcb_info if isinstance(tcb_info, dict) else None


def check_sigstore_links(links):
    """Check that Sigstore links are accessible (not 404)."""
    results = []
    for link in links:
        try:
            response = requests.head(link, timeout=10, allow_redirects=True)
            accessible = response.status_code < 400
            results.append((link, accessible, response.status_code))
        except requests.RequestException as e:
            results.append((link, False, str(e)))
    return results


def show_sigstore_provenance(attestation):
    """Extract and display Sigstore provenance links from attestation."""
    tcb_info = _parsed_tcb_info(attestation) or {}
    compose = tcb_info.get("app_compose")
    if not compose:
        return

    sigstore_links = extract_sigstore_links(compose)
    if not sigstore_links:
        return

    print("\n🔐 Sigstore provenance")
    print("Checking Sigstore accessibility for container images...")
    link_results = check_sigstore_links(sigstore_links)

    for link, accessible, status in link_results:
        if accessible:
            print(f"  ✓ {link} (HTTP {status})")
        else:
            print(f"  ✗ {link} (HTTP {status})")


def show_compose(attestation, intel_result):
    """Display the Docker compose manifest and verify against mr_config from verified quote."""
    tcb_info = _parsed_tcb_info(attestation) or {}
    app_compose = tcb_info.get("app_compose")
    if not app_compose:
        return
    docker_compose = json.loads(app_compose)["docker_compose_file"]
    print("\nDocker compose manifest attested by the enclave:")
    print(docker_compose)

    compose_hash = sha256(app_compose.encode()).hexdigest()
    print("Compose sha256:", compose_hash)

    mr_config = intel_result["quote"]["body"]["mrconfig"]
    print("mr_config (from verified quote):", mr_config)
    expected_mr_config = "01" + compose_hash
    print("mr_config matches compose hash:", mr_config.lower().startswith(expected_mr_config.lower()))


async def verify_attestation(attestation, request_nonce, verify_model=False):
    """Verify the attestation.

    When attestation contains tls_cert_fingerprint (from include_tls_fingerprint),
    report_data[0..32] = SHA256(signing_address || fingerprint) is verified automatically.
    """
    print("\n🔐 Attestation")

    print("Request nonce:", request_nonce)

    if "signing_address" in attestation:
        print("\nSigning address:", attestation["signing_address"])

    print("\n🔐 Intel TDX quote")
    intel_result = await check_tdx_quote(attestation)

    print("\n🔐 TDX report data")
    check_report_data(attestation, request_nonce, intel_result)

    if verify_model:
        print("\n🔐 GPU attestation")
        check_gpu(attestation, request_nonce)

    show_compose(attestation, intel_result)
    show_sigstore_provenance(attestation)
    check_compose_manager_actions(attestation)


async def verify_gateway_tls_binding(signing_address, model, signing_algo="ecdsa"):
    """Gateway-only verification with TLS fingerprint binding."""
    request_nonce = secrets.token_hex(32)
    report = fetch_report(model, request_nonce, signing_algo=signing_algo, include_tls=True, signing_address=signing_address)
    gateway = report.get("gateway_attestation")

    if not gateway:
        print("No gateway_attestation in report (cannot verify TLS binding).")
        return
    if not gateway.get("tls_cert_fingerprint"):
        print(
            "TLS verification requested but gateway has no tls_cert_fingerprint "
            "(configure the gateway to include a TLS certificate fingerprint in attestation, or omit --verify-tls)."
        )
        return

    print("========================================")
    print("🔐 Gateway attestation (include_tls_fingerprint)")
    print("========================================")
    await verify_attestation(gateway, request_nonce, verify_model=False)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud TEE Attestation")
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument("--verify-tls", action="store_true", help="Fetch with include_tls_fingerprint and verify TLS fingerprint binding on gateway")
    args = parser.parse_args()

    request_nonce = secrets.token_hex(32)
    report = fetch_report(args.model, request_nonce, signing_algo="ecdsa", include_tls=args.verify_tls)

    print("========================================")
    print("🔐 Gateway attestation")
    print("========================================")
    gateway_attestation = report.get("gateway_attestation")
    if gateway_attestation:
        await verify_attestation(gateway_attestation, request_nonce, verify_model=False)

    model_attestations = report.get("model_attestations", [])
    index = 0
    for model_attestation in model_attestations:
        index += 1
        print("\n\n\n========================================")
        print(f"🔐 Model attestations: (#{index})")
        print("========================================")
        await verify_attestation(model_attestation, request_nonce, verify_model=True)

    # Top-level compose-manager attestation (present on model proxy responses)
    check_compose_manager_actions(report)

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
