#!/usr/bin/env python3
"""Test end-to-end encryption for NEAR AI Cloud chat completions."""

import argparse
import asyncio
import json
import os

import requests
from encryption_utils import (
    decrypt_text,
    encrypt_text,
    fetch_model_public_key as fetch_model_public_key_util,
    generate_ecdsa_key_pair,
    generate_ed25519_key_pair,
)

from chat_verifier import verify_chat

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")
MAX_TOKENS = 100


def fetch_model_public_key(model, signing_algo="ecdsa"):
    """Fetch model public key from attestation report."""
    return fetch_model_public_key_util(
        base_url=BASE_URL, api_key=API_KEY, model=model, signing_algo=signing_algo
    )


def encrypt_message_content(
    message_content: str, model_public_key: str, signing_algo: str
) -> str:
    """Encrypt message content using model's public key."""
    return encrypt_text(message_content, model_public_key, signing_algo)


def decrypt_message_content(
    encrypted_hex: str, client_private_key, signing_algo: str
) -> str:
    """Decrypt message content using client's private key."""
    return decrypt_text(encrypted_hex, client_private_key, signing_algo)


async def encrypted_streaming_example(model, signing_algo="ecdsa"):
    """Example of encrypted streaming chat completion."""
    print(f"\n{'='*60}")
    print(f"Encrypted Streaming Example ({signing_algo.upper()})")
    print(f"{'='*60}")

    # Fetch model public key
    try:
        model_pub_key = fetch_model_public_key(model, signing_algo)
        print(f"✓ Fetched model public key: {model_pub_key}")
    except Exception as e:
        print(f"✗ Failed to fetch model public key: {e}")
        return

    # Generate client key pair
    try:
        if signing_algo == "ecdsa":
            client_priv_key_hex, client_pub_key_hex, client_priv_key = (
                generate_ecdsa_key_pair()
            )
        else:
            client_priv_key_hex, client_pub_key_hex, client_priv_key = (
                generate_ed25519_key_pair()
            )
        print(f"✓ Generated client key pair: {client_pub_key_hex[:32]}...")
    except Exception as e:
        print(f"✗ Failed to generate client key pair: {e}")
        return

    # Prepare message
    original_content = "Hello, how are you?"
    try:
        encrypted_content = encrypt_message_content(
            original_content, model_pub_key, signing_algo
        )
        print(f"✓ Encrypted message content: {encrypted_content}")
    except Exception as e:
        print(f"✗ Failed to encrypt message: {e}")
        return

    body = {
        "model": model,
        "messages": [{"role": "user", "content": encrypted_content}],
        "stream": True,
        "max_tokens": MAX_TOKENS,
    }
    body_json = json.dumps(body)

    # Make request with encryption headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Signing-Algo": signing_algo,
        "X-Client-Pub-Key": client_pub_key_hex,
        "X-Model-Pub-Key": model_pub_key,
    }

    try:
        response = requests.post(
            f"{BASE_URL}/v1/chat/completions",
            headers=headers,
            data=body_json,
            stream=True,
            timeout=30,
        )
        response.raise_for_status()
        print(f"✓ Request sent successfully (HTTP {response.status_code})")
    except requests.exceptions.HTTPError as e:
        print(f"✗ Request failed: {e}")
        if e.response is not None:
            print(f"  Status code: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"  Error detail: {json.dumps(error_detail, indent=2)}")
            except Exception as e:
                print(f"✗ Failed to parse error detail: {e}")
                print(f"  Response text: {e.response.text[:200]}")
        return
    except Exception as e:
        print(f"✗ Request failed: {e}")
        return

    chat_id = None
    response_text = ""
    decrypted_content = ""

    print("\nReceiving stream...")
    for chunk in response.iter_lines():
        line = chunk.decode() if chunk else ""
        response_text += line + "\n"

        if line.startswith("data: {") and chat_id is None:
            try:
                data = json.loads(line[6:])
                if "id" in data:
                    chat_id = data["id"]
                    print(f"✓ Chat ID: {chat_id}")
            except Exception as e:
                print(f"✗ Failed to parse chat ID: {e}")
                print(f"  Line: {line}")

        # Try to decrypt content from streaming chunks
        if line.startswith("data: {") and not line.endswith("[DONE]"):
            try:
                data = json.loads(line[6:])
                if "choices" in data and len(data["choices"]) > 0:
                    delta = data["choices"][0].get("delta", {})
                    if "content" in delta:
                        content_hex = delta["content"]
                        if isinstance(content_hex, str) and len(content_hex) > 0:
                            try:
                                decrypted_chunk = decrypt_message_content(
                                    content_hex, client_priv_key, signing_algo
                                )
                                decrypted_content += decrypted_chunk
                                print(f"  Decrypted chunk: {decrypted_chunk}\n", end="", flush=True)
                            except Exception as e:
                                print(f"✗ Failed to decrypt content: {e}")
                                print(f"  Encrypted content: {content_hex}")
            except Exception as e:
                print(f"✗ Failed to decrypt content: {e}")
                print(f"  Encrypted content: {line}")

    print(f"\n\n✓ Complete decrypted response: {decrypted_content}")
    print(f"✓ Total response length: {len(response_text)} bytes")

    if chat_id:
        await verify_chat(
            chat_id,
            body_json,
            response_text,
            f"Verifying Encrypted Streaming ({signing_algo.upper()})",
            model,
        )


async def encrypted_non_streaming_example(model, signing_algo="ecdsa"):
    """Example of encrypted non-streaming chat completion."""
    print(f"\n{'='*60}")
    print(f"Encrypted Non-Streaming Example ({signing_algo.upper()})")
    print(f"{'='*60}")

    # Fetch model public key
    try:
        model_pub_key = fetch_model_public_key(model, signing_algo)
        print(f"✓ Fetched model public key: {model_pub_key}")
    except Exception as e:
        print(f"✗ Failed to fetch model public key: {e}")
        return

    # Generate client key pair
    try:
        if signing_algo == "ecdsa":
            client_priv_key_hex, client_pub_key_hex, client_priv_key = (
                generate_ecdsa_key_pair()
            )
        else:
            client_priv_key_hex, client_pub_key_hex, client_priv_key = (
                generate_ed25519_key_pair()
            )
        print(f"✓ Generated client key pair: {client_pub_key_hex[:32]}...")
    except Exception as e:
        print(f"✗ Failed to generate client key pair: {e}")
        return

    # Prepare message
    original_content = "Hello, how are you?"
    try:
        encrypted_content = encrypt_message_content(
            original_content, model_pub_key, signing_algo
        )
        print(f"✓ Encrypted message content: {encrypted_content}")
    except Exception as e:
        print(f"✗ Failed to encrypt message: {e}")
        return

    body = {
        "model": model,
        "messages": [{"role": "user", "content": encrypted_content}],
        "stream": False,
        "max_tokens": MAX_TOKENS,
    }
    body_json = json.dumps(body)

    # Make request with encryption headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Signing-Algo": signing_algo,
        "X-Client-Pub-Key": client_pub_key_hex,
        "X-Model-Pub-Key": model_pub_key,
    }

    try:
        response = requests.post(
            f"{BASE_URL}/v1/chat/completions",
            headers=headers,
            data=body_json,
            timeout=30,
        )
        response.raise_for_status()
        print(f"✓ Request sent successfully (HTTP {response.status_code})")
    except requests.exceptions.HTTPError as e:
        print(f"✗ Request failed: {e}")
        if e.response is not None:
            print(f"  Status code: {e.response.status_code}")
            try:
                error_detail = e.response.json()
                print(f"  Error detail: {json.dumps(error_detail, indent=2)}")
            except Exception as e:
                print(f"✗ Failed to parse error detail: {e}")
                print(f"  Response text: {e.response.text[:200]}")
        return
    except Exception as e:
        print(f"✗ Request failed: {e}")
        return

    payload = response.json()
    chat_id = payload.get("id", "unknown")
    print(f"✓ Chat ID: {chat_id}")

    # Check finish_reason to see if response was truncated
    if "choices" in payload and len(payload["choices"]) > 0:
        choice = payload["choices"][0]
        finish_reason = choice.get("finish_reason", "unknown")
        print(f"✓ Finish reason: {finish_reason}")
        if finish_reason == "length":
            print(f"  ⚠ Response was truncated due to max_tokens limit")

    # Decrypt response content (including all encrypted fields)
    if "choices" in payload and len(payload["choices"]) > 0:
        message = payload["choices"][0].get("message", {})

        # Decrypt all encrypted fields: content, reasoning_content, reasoning
        decrypted_fields = {}
        for field in ["content", "reasoning_content", "reasoning"]:
            if field in message and message[field]:
                encrypted_value = message[field]
                # Check if it looks like encrypted hex (even length, hex chars, reasonably long)
                if isinstance(encrypted_value, str) and len(encrypted_value) > 64:
                    if len(encrypted_value) % 2 == 0 and all(
                        c in "0123456789abcdefABCDEF" for c in encrypted_value
                    ):
                        try:
                            decrypted_value = decrypt_message_content(
                                encrypted_value, client_priv_key, signing_algo
                            )
                            decrypted_fields[field] = decrypted_value
                            print(f"✓ Decrypted {field} ({len(decrypted_value)} chars)")
                        except Exception as e:
                            print(f"✗ Failed to decrypt {field}: {e}")
                            print(
                                f"  Encrypted {field} (first 100 chars): {encrypted_value[:100]}"
                            )
                    else:
                        # Not encrypted, just plain text
                        decrypted_fields[field] = encrypted_value
                        print(f"✓ {field} (plain text, {len(encrypted_value)} chars)")
                elif encrypted_value:
                    # Short value or not hex - might be plain text
                    decrypted_fields[field] = encrypted_value
                    print(f"✓ {field} (plain text, {len(encrypted_value)} chars)")

        if decrypted_fields:
            # Show complete decrypted response
            if "content" in decrypted_fields:
                content = decrypted_fields["content"]
                print(f"\n✓ Complete decrypted response ({len(content)} characters):")
                print(f"  {content}")
                if "reasoning_content" in decrypted_fields:
                    reasoning = decrypted_fields["reasoning_content"]
                    print(f"\n✓ Reasoning content ({len(reasoning)} characters):")
                    print(f"  {reasoning}")
                if "reasoning" in decrypted_fields:
                    reasoning_alt = decrypted_fields["reasoning"]
                    print(f"\n✓ Reasoning (alt) ({len(reasoning_alt)} characters):")
                    print(f"  {reasoning_alt}")
            else:
                print(f"\n⚠ No content field found in decrypted fields")
        else:
            print(f"\n⚠ No encrypted fields found to decrypt")
            print(f"  Message keys: {list(message.keys())}")
            print(f"  Message: {json.dumps(message, indent=2)}")
    else:
        print("✗ No choices in response")
        print(f"  Response: {json.dumps(payload, indent=2)}")

    await verify_chat(
        chat_id,
        body_json,
        response.text,
        f"Verifying Encrypted Non-Streaming ({signing_algo.upper()})",
        model,
    )


async def main():
    """Run encryption test examples."""
    parser = argparse.ArgumentParser(
        description="Test End-to-End Encryption for NEAR AI Cloud Chat"
    )
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument(
        "--signing-algo",
        choices=["ecdsa", "ed25519"],
        default="ecdsa",
        help="Signing algorithm",
    )
    parser.add_argument(
        "--test-both", action="store_true", help="Test both ECDSA and Ed25519"
    )
    args = parser.parse_args()

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        print("Set it with: export API_KEY=your-api-key")
        return

    if args.test_both:
        # Test both algorithms
        await encrypted_streaming_example(args.model, "ecdsa")
        await encrypted_non_streaming_example(args.model, "ecdsa")
        await encrypted_streaming_example(args.model, "ed25519")
        await encrypted_non_streaming_example(args.model, "ed25519")
    else:
        await encrypted_streaming_example(args.model, args.signing_algo)
        await encrypted_non_streaming_example(args.model, args.signing_algo)


if __name__ == "__main__":
    asyncio.run(main())
