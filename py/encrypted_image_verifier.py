#!/usr/bin/env python3
"""Test end-to-end encryption for NEAR AI Cloud image generation."""

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

from image_verifier import verify_image

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")


def fetch_model_public_key(model, signing_algo="ecdsa"):
    """Fetch model public key from attestation report."""
    return fetch_model_public_key_util(
        base_url=BASE_URL, api_key=API_KEY, model=model, signing_algo=signing_algo
    )


def encrypt_prompt(prompt: str, model_public_key: str, signing_algo: str) -> str:
    """Encrypt prompt using model's public key."""
    return encrypt_text(prompt, model_public_key, signing_algo)


def decrypt_prompt(encrypted_hex: str, client_private_key, signing_algo: str) -> str:
    """Decrypt prompt using client's private key."""
    return decrypt_text(encrypted_hex, client_private_key, signing_algo)


async def encrypted_image_generation_example(model, signing_algo="ecdsa"):
    """Example of encrypted image generation."""
    print(f"\n{'='*60}")
    print(f"Encrypted Image Generation Example ({signing_algo.upper()})")
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

    # Prepare prompt
    original_prompt = "a beautiful sunset over mountains"
    try:
        encrypted_prompt = encrypt_prompt(original_prompt, model_pub_key, signing_algo)
        print(f"✓ Encrypted prompt: {encrypted_prompt}")
    except Exception as e:
        print(f"✗ Failed to encrypt prompt: {e}")
        return

    body = {
        "model": model,
        "prompt": encrypted_prompt,
        "size": "1024x1024",
        "n": 1,
        "response_format": "b64_json",
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
            f"{BASE_URL}/v1/images/generations",
            headers=headers,
            data=body_json,
            timeout=60,
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
    image_id = payload.get("id")
    if not image_id:
        print("Error: Response does not contain 'id' field")
        print("Response:", json.dumps(payload, indent=2))
        return
    print(f"✓ Image ID: {image_id}")

    # Decrypt response fields if encryption is enabled
    if "data" in payload and len(payload["data"]) > 0:
        print(f"✓ Generated {len(payload['data'])} image(s)")
        for i, item in enumerate(payload["data"]):
            # Decrypt b64_json if present and encrypted
            if "b64_json" in item and item["b64_json"]:
                encrypted_b64 = item["b64_json"]
                # Check if it looks like encrypted hex (even length, hex chars, reasonably long)
                if isinstance(encrypted_b64, str) and len(encrypted_b64) > 64:
                    if len(encrypted_b64) % 2 == 0 and all(
                        c in "0123456789abcdefABCDEF" for c in encrypted_b64
                    ):
                        try:
                            decrypted_b64 = decrypt_prompt(encrypted_b64, client_priv_key, signing_algo)
                            print(f"✓ Decrypted b64_json for image {i+1} ({len(decrypted_b64)} chars)")
                            # Optionally save the decrypted image
                            # import base64
                            # img_data = base64.b64decode(decrypted_b64)
                            # with open(f"decrypted_image_{i+1}.png", "wb") as f:
                            #     f.write(img_data)
                        except Exception as e:
                            print(f"✗ Failed to decrypt b64_json for image {i+1}: {e}")
            
            # Decrypt revised_prompt if present and encrypted
            if "revised_prompt" in item and item["revised_prompt"]:
                encrypted_prompt = item["revised_prompt"]
                # Check if it looks like encrypted hex
                if isinstance(encrypted_prompt, str) and len(encrypted_prompt) > 64:
                    if len(encrypted_prompt) % 2 == 0 and all(
                        c in "0123456789abcdefABCDEF" for c in encrypted_prompt
                    ):
                        try:
                            decrypted_prompt = decrypt_prompt(encrypted_prompt, client_priv_key, signing_algo)
                            print(f"✓ Decrypted revised_prompt for image {i+1}: {decrypted_prompt}")
                        except Exception as e:
                            print(f"✗ Failed to decrypt revised_prompt for image {i+1}: {e}")

    await verify_image(
        image_id,
        body_json,
        response.text,
        f"Verifying Encrypted Image Generation ({signing_algo.upper()})",
        model,
    )


async def main():
    """Run encryption test examples."""
    parser = argparse.ArgumentParser(
        description="Test End-to-End Encryption for NEAR AI Cloud Image Generation"
    )
    parser.add_argument("--model", default="Qwen/Qwen-Image")
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
        await encrypted_image_generation_example(args.model, "ecdsa")
        await encrypted_image_generation_example(args.model, "ed25519")
    else:
        await encrypted_image_generation_example(args.model, args.signing_algo)


if __name__ == "__main__":
    asyncio.run(main())

