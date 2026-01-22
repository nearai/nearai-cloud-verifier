#!/usr/bin/env python3
"""Minimal guide for checking signed image generation responses."""

import argparse
import asyncio
import json
import os
import secrets
from hashlib import sha256

import requests
from eth_account import Account
from eth_account.messages import encode_defunct

from model_verifier import (
    check_report_data,
    check_gpu,
    check_tdx_quote,
    show_sigstore_provenance,
)

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")


def sha256_text(text):
    """Calculate SHA256 hash of text."""
    return sha256(text.encode()).hexdigest()


def fetch_signature(image_id, model, signing_algo="ecdsa"):
    """Fetch signature for an image generation."""
    url = f"{BASE_URL}/v1/signature/{image_id}?model={model}&signing_algo={signing_algo}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get(url, headers=headers, timeout=30).json()


def recover_signer(text, signature):
    """Recover Ethereum address from ECDSA signature."""
    message = encode_defunct(text=text)
    return Account.recover_message(message, signature=signature)


def fetch_attestation_for(signing_address, model):
    """Fetch attestation for a specific signing address."""
    nonce = secrets.token_hex(32)
    url = f"{BASE_URL}/v1/attestation/report?model={model}&nonce={nonce}&signing_algo=ecdsa&signing_address={signing_address}"
    report = requests.get(url, timeout=30).json()

    # Handle both single attestation and multi-node response formats
    if "model_attestations" in report:
        # Multi-node format: find the attestation matching the signing address
        attestation = next(
            item for item in report["model_attestations"]
            if item["signing_address"].lower() == signing_address.lower()
        )
    else:
        # Single attestation format: use the report directly
        attestation = report

    return attestation, nonce


async def check_attestation(signing_address, attestation, nonce):
    """Verify attestation for a signing address (calls check_report_data, check_gpu, check_tdx_quote)."""
    intel_result = await check_tdx_quote(attestation)
    check_report_data(attestation, nonce, intel_result)
    check_gpu(attestation, nonce)
    show_sigstore_provenance(attestation)


async def verify_image(image_id, request_body, response_text, label, model):
    """Verify an image generation signature and attestation."""
    request_hash = sha256_text(request_body)
    response_hash = sha256_text(response_text)

    print(f"\n--- {label} ---")
    signature_payload = fetch_signature(image_id, model)
    print(json.dumps(signature_payload, indent=2))

    hashed_text = signature_payload["text"]
    request_hash_server, response_hash_server = hashed_text.split(":")
    print("Request hash matches:", request_hash == request_hash_server)
    print("Response hash matches:", response_hash == response_hash_server)

    signature = signature_payload["signature"]
    signing_address = signature_payload["signing_address"]
    recovered = recover_signer(hashed_text, signature)
    print("Signature valid:", recovered.lower() == signing_address.lower())

    attestation, nonce = fetch_attestation_for(signing_address, model)
    if not isinstance(attestation, dict) or attestation.get("error"):
        print("Attestation not found for signing address:", signing_address, ".", attestation)
        return
    print("\nAttestation signer:", attestation["signing_address"])
    print("Attestation nonce:", nonce)
    await check_attestation(signing_address, attestation, nonce)


async def image_generation_example(model):
    """Example of image generation verification."""
    body = {
        "model": model,
        "prompt": "a beautiful sunset over mountains",
        "size": "1024x1024",
        "n": 1,
        "response_format": "b64_json",
    }
    body_json = json.dumps(body)
    response = requests.post(
        f"{BASE_URL}/v1/images/generations",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        data=body_json,
        timeout=60,  # Image generation may take longer
    )

    payload = response.json()
    # The response from the provider includes an 'id' field
    # Extract it from the response
    image_id = payload.get("id")
    if not image_id:
        print("Error: Response does not contain 'id' field")
        print("Response:", json.dumps(payload, indent=2))
        return

    await verify_image(image_id, body_json, response.text, "Image generation example", model)


async def main():
    """Run example verification of image generation."""
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud Signed Image Generation Responses")
    parser.add_argument("--model", default="Qwen/Qwen-Image")
    args = parser.parse_args()

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        print("Set it with: export API_KEY=your-api-key")
        return
    await image_generation_example(args.model)


if __name__ == "__main__":
    asyncio.run(main())

