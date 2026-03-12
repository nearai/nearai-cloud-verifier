#!/usr/bin/env python3
"""Minimal guide for checking signed chat responses."""

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
    verify_gateway_tls_binding,
)

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")


def sha256_text(text):
    """Calculate SHA256 hash of text."""
    return sha256(text.encode()).hexdigest()


def fetch_signature(chat_id, model, signing_algo="ecdsa"):
    """Fetch signature for a chat completion."""
    url = f"{BASE_URL}/v1/signature/{chat_id}?model={model}&signing_algo={signing_algo}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get(url, headers=headers, timeout=30).json()


def recover_signer(text, signature):
    """Recover Ethereum address from ECDSA signature."""
    message = encode_defunct(text=text)
    return Account.recover_message(message, signature=signature)


def fetch_attestation_for(signing_address, model):
    """Fetch attestation for a specific signing address (model path; no include_tls)."""
    nonce = secrets.token_hex(32)
    url = f"{BASE_URL}/v1/attestation/report?model={model}&nonce={nonce}&signing_algo=ecdsa&signing_address={signing_address}"
    report = requests.get(url, timeout=30).json()

    if "model_attestations" in report:
        attestation = next(
            item for item in report["model_attestations"]
            if item["signing_address"].lower() == signing_address.lower()
        )
    else:
        attestation = report

    return attestation, nonce


async def check_attestation(signing_address, attestation, nonce):
    """Verify model attestation. TLS PEM binding lives in model_verifier.verify_gateway_tls_binding."""
    intel_result = await check_tdx_quote(attestation)
    check_report_data(attestation, nonce, intel_result)
    check_gpu(attestation, nonce)
    show_sigstore_provenance(attestation)


async def verify_chat(chat_id, request_body, response_text, label, model, verify_tls=False):
    """Verify a chat completion signature and attestation."""
    request_hash = sha256_text(request_body)
    response_hash = sha256_text(response_text)

    print(f"\n--- {label} ---")
    signature_payload = fetch_signature(chat_id, model)
    print(json.dumps(signature_payload, indent=2))

    hashed_text = signature_payload["text"]
    parts = hashed_text.split(":")
    if len(parts) not in (2, 3):
        raise ValueError(
            f"Invalid signature payload text format: expected 2 or 3 colon-separated parts, "
            f"got {len(parts)}: {hashed_text!r}"
        )
    if len(parts) == 3:
        request_hash_server, response_hash_server = parts[1], parts[2]
    else:
        request_hash_server, response_hash_server = parts[0], parts[1]
    print("Request hash matches:", request_hash == request_hash_server)
    print("Response hash matches:", response_hash == response_hash_server)

    signature = signature_payload["signature"]
    signing_address = signature_payload["signing_address"]
    recovered = recover_signer(hashed_text, signature)
    print("Signature valid:", recovered.lower() == signing_address.lower())

    if verify_tls:
        await verify_gateway_tls_binding(signing_address, model)

    attestation, nonce = fetch_attestation_for(signing_address, model)
    if not isinstance(attestation, dict) or attestation.get("error"):
        print("Attestation not found for signing address:", signing_address, ".", attestation)
        return
    print("\nAttestation signer:", attestation["signing_address"])
    print("Attestation nonce:", nonce)
    await check_attestation(signing_address, attestation, nonce)


async def streaming_example(model, verify_tls=False):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": True,
        "max_tokens": 1,
    }
    body_json = json.dumps(body)
    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        data=body_json,
        stream=True,
        timeout=30,
    )

    chat_id = None
    response_text = ""
    for chunk in response.iter_lines():
        line = chunk.decode()
        response_text += line + "\n"
        if line.startswith("data: {") and chat_id is None:
            chat_id = json.loads(line[6:])["id"]

    await verify_chat(chat_id, body_json, response_text, "Streaming example", model, verify_tls)


async def non_streaming_example(model, verify_tls=False):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": False,
        "max_tokens": 1,
    }
    body_json = json.dumps(body)
    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"},
        data=body_json,
        timeout=30,
    )

    payload = response.json()
    chat_id = payload["id"]
    await verify_chat(chat_id, body_json, response.text, "Non-streaming example", model, verify_tls)


async def main():
    parser = argparse.ArgumentParser(description="Verify NEAR AI Cloud Signed Chat Responses")
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Run gateway TLS PEM binding via model_verifier.verify_gateway_tls_binding",
    )
    args = parser.parse_args()

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        return
    if args.verify_tls:
        print("TLS PEM binding: model_verifier.verify_gateway_tls_binding (--verify-tls)")
    await streaming_example(args.model, args.verify_tls)
    await non_streaming_example(args.model, args.verify_tls)


if __name__ == "__main__":
    asyncio.run(main())
