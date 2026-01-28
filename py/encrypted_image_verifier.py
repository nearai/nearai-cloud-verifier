#!/usr/bin/env python3
"""Test end-to-end encryption for NEAR AI Cloud image generation."""

import argparse
import asyncio
import json
import os
import secrets

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from nacl.public import (
    PrivateKey as X25519PrivateKeyNaCl,
    PublicKey as X25519PublicKeyNaCl,
    Box,
)
from nacl import bindings

from image_verifier import verify_image

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")


def fetch_model_public_key(model, signing_algo="ecdsa"):
    """Fetch model public key from attestation report."""
    url = f"{BASE_URL}/v1/attestation/report?model={model}&signing_algo={signing_algo}"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    report = requests.get(url, headers=headers, timeout=30).json()

    # Try to get signing_public_key from model_attestations
    if "model_attestations" in report:
        for attestation in report["model_attestations"]:
            if "signing_public_key" in attestation:
                return attestation["signing_public_key"]

    raise ValueError(
        f"Could not find signing_public_key for model {model} with algorithm {signing_algo}"
    )


def generate_ecdsa_key_pair():
    """Generate ECDSA key pair and return (private_key_hex, public_key_hex, private_key_obj)."""
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    # Get private key bytes (32 bytes)
    # SECP256K1 doesn't support Raw format, so we extract the integer value
    private_numbers = private_key.private_numbers()
    private_key_int = private_numbers.private_value
    # Convert to 32-byte big-endian representation
    private_key_bytes = private_key_int.to_bytes(32, byteorder="big")

    # Get public key bytes (uncompressed, 65 bytes with 0x04 prefix)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # Remove 0x04 prefix for public key (64 bytes)
    public_key_hex = public_key_bytes[1:].hex()
    private_key_hex = private_key_bytes.hex()

    return private_key_hex, public_key_hex, private_key


def generate_ed25519_key_pair():
    """Generate Ed25519 key pair and return (private_key_hex, public_key_hex, private_key_obj)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Get private key bytes (32 bytes seed)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Get public key bytes (32 bytes)
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return private_key_bytes.hex(), public_key_bytes.hex(), private_key


def encrypt_ecdsa(data: bytes, public_key_hex: str) -> bytes:
    """Encrypt data using ECDSA public key (ECIES)."""
    # Parse public key from hex
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
        public_key_bytes = public_key_bytes[1:]  # Remove 0x04 prefix

    if len(public_key_bytes) != 64:
        raise ValueError(
            f"ECDSA public key must be 64 bytes, got {len(public_key_bytes)}"
        )

    # Create EC public key
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x04" + public_key_bytes
    )

    # Generate ephemeral EC key pair
    ephemeral_private = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()

    # Perform ECDH key exchange
    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

    # Derive AES key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdsa_encryption",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)

    # Encrypt with AES-GCM
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    # Format: [ephemeral_public_key (65 bytes)][nonce (12 bytes)][ciphertext]
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return ephemeral_public_bytes + nonce + ciphertext


def decrypt_ecdsa(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt data using ECDSA private key."""
    if len(encrypted_data) < 93:
        raise ValueError("Encrypted data too short")

    # Extract components
    ephemeral_public_bytes = encrypted_data[:65]
    nonce = encrypted_data[65:77]
    ciphertext = encrypted_data[77:]

    # Parse ephemeral public key
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), ephemeral_public_bytes
    )

    # Use the private key object directly for ECDH exchange
    # private_key_obj is already an EllipticCurvePrivateKey
    shared_secret = private_key_obj.exchange(ec.ECDH(), ephemeral_public)

    # Derive AES key using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdsa_encryption",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)

    # Decrypt with AES-GCM
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext


def encrypt_ed25519(data: bytes, public_key_hex: str) -> bytes:
    """Encrypt data using Ed25519 public key via PyNaCl Box (X25519 + ChaCha20-Poly1305)."""
    # Parse public key from hex
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}"
        )

    # Convert Ed25519 public key to X25519 public key (PyNaCl format)
    x25519_public = X25519PublicKeyNaCl(
        bindings.crypto_sign_ed25519_pk_to_curve25519(public_key_bytes)
    )

    # Generate ephemeral X25519 key pair using PyNaCl
    ephemeral_private = X25519PrivateKeyNaCl.generate()
    ephemeral_public = ephemeral_private.public_key

    # Create Box for encryption
    box = Box(ephemeral_private, x25519_public)

    # Encrypt using PyNaCl Box
    encrypted = box.encrypt(data)

    # Format: [ephemeral_public_key (32 bytes)][nonce (24 bytes)][ciphertext]
    ephemeral_public_bytes = bytes(ephemeral_public)
    return ephemeral_public_bytes + encrypted


def decrypt_ed25519(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt data using Ed25519 private key via PyNaCl Box."""
    if len(encrypted_data) < 72:
        raise ValueError("Encrypted data too short")

    # Extract components
    ephemeral_public_bytes = encrypted_data[:32]
    box_encrypted = encrypted_data[32:]  # Contains [nonce (24 bytes)][ciphertext]

    # Get Ed25519 private key and convert to X25519 private (PyNaCl format)
    seed_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key_bytes = private_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ed25519_secret_key = seed_bytes + public_key_bytes
    x25519_private_bytes = bindings.crypto_sign_ed25519_sk_to_curve25519(
        ed25519_secret_key
    )
    x25519_private = X25519PrivateKeyNaCl(x25519_private_bytes)

    # Convert ephemeral public key to X25519 (PyNaCl format)
    ephemeral_public = X25519PublicKeyNaCl(ephemeral_public_bytes)

    # Create Box for decryption
    box = Box(x25519_private, ephemeral_public)

    # Decrypt using PyNaCl Box
    plaintext = box.decrypt(box_encrypted)

    return plaintext


def encrypt_prompt(prompt: str, model_public_key: str, signing_algo: str) -> str:
    """Encrypt prompt using model's public key."""
    data = prompt.encode("utf-8")
    if signing_algo == "ecdsa":
        encrypted = encrypt_ecdsa(data, model_public_key)
    elif signing_algo == "ed25519":
        encrypted = encrypt_ed25519(data, model_public_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return encrypted.hex()


def decrypt_prompt(encrypted_hex: str, client_private_key, signing_algo: str) -> str:
    """Decrypt prompt using client's private key."""
    encrypted_data = bytes.fromhex(encrypted_hex)
    if signing_algo == "ecdsa":
        decrypted = decrypt_ecdsa(encrypted_data, client_private_key)
    elif signing_algo == "ed25519":
        decrypted = decrypt_ed25519(encrypted_data, client_private_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return decrypted.decode("utf-8")


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

