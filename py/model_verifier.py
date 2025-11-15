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


def fetch_report(model, nonce, signing_algo="ecdsa"):
    """Fetch attestation report from the API.

    Args:
        model: The model name to fetch the report for
        nonce: The nonce for the request
        signing_algo: The signing algorithm to use (defaults to "ecdsa")

    Returns:
        dict: The attestation report
    """
    url = f"{BASE_URL}/v1/attestation/report?model={model}&nonce={nonce}&signing_algo={signing_algo}"
    return requests.get(url, timeout=30, headers={"Authorization": f"Bearer {API_KEY}"}).json()

def fetch_nvidia_verification(payload):
    """Submit GPU evidence to NVIDIA NRAS for verification."""
    return requests.post(GPU_VERIFIER_API, json=payload, timeout=30).json()


def base64url_decode_jwt_payload(jwt_token):
    """Decode the payload section of a JWT token."""
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    return base64.urlsafe_b64decode(padded).decode()


def check_report_data(attestation, request_nonce, intel_result):
    """Verify that TDX report data binds the signing address and request nonce.

    Returns dict with verification results.
    """
    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = bytes.fromhex(report_data_hex.removeprefix("0x"))
    signing_address = attestation["signing_address"]
    signing_algo = attestation.get("signing_algo", "ecdsa").lower()

    # Parse signing address bytes based on algorithm
    if signing_algo == "ecdsa":
        addr_hex = signing_address.removeprefix("0x")
        signing_address_bytes = bytes.fromhex(addr_hex)
    else:
        signing_address_bytes = bytes.fromhex(signing_address)

    embedded_address = report_data[:32]
    embedded_nonce = report_data[32:]

    binds_address = embedded_address == signing_address_bytes.ljust(32, b"\x00")
    embeds_nonce = embedded_nonce.hex() == request_nonce

    print("Signing algorithm:", signing_algo)
    print("Report data binds signing address:", binds_address)
    if not binds_address:
        print("Report data binds signing address:", "expected:", signing_address_bytes.hex(), "actual:", embedded_address.hex())
    print("Report data embeds request nonce:", embeds_nonce)
    if not embeds_nonce:
        print("Report data embeds request nonce:", "expected:", request_nonce, "actual:", embedded_nonce.hex())

    return {
        "binds_address": binds_address,
        "embeds_nonce": embeds_nonce,
    }


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

    # Create a result structure similar to the remote verification
    intel_result = {
        "quote": {
            "body": {
                "reportdata": report_data,
                "mrconfig": mr_config
            }
        },
        "verified": result.status == "UpToDate" if hasattr(result, 'status') else False
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
    tcb_info = attestation.get("info", {}).get("tcb_info", {})
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
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
    tcb_info = attestation["info"]["tcb_info"]
    if isinstance(tcb_info, str):
        tcb_info = json.loads(tcb_info)
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
    """Verify the attestation."""
    print("\n🔐 Attestation")
    # print(attestation)

    print("Request nonce:", request_nonce)

    if verify_model:
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


async def main() -> None:
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud TEE Attestation")
    parser.add_argument("--model", default="deepseek-v3.1")
    args = parser.parse_args()

    request_nonce = secrets.token_hex(32)
    report = fetch_report(args.model, request_nonce, signing_algo="ecdsa")

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

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
