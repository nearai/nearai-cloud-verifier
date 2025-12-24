#!/usr/bin/env python3
"""Test end-to-end encryption for NEAR AI Cloud chat completions."""

import argparse
import asyncio
import json
import os

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

from chat_verifier import verify_chat

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
    elif "signing_public_key" in report:
        return report["signing_public_key"]

    raise ValueError(
        f"Could not find signing_public_key for model {model} with algorithm {signing_algo}"
    )


def generate_ecdsa_key_pair():
    """Generate ECDSA key pair and return (private_key_hex, public_key_hex, private_key_obj)."""
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    # Get private key bytes (32 bytes)
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

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
    nonce = os.urandom(12)
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

    # Get private key bytes and create EC private key
    private_key_bytes = private_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, "big"), ec.SECP256K1(), default_backend()
    )

    # Perform ECDH key exchange
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

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


def encrypt_message_content(
    message_content: str, model_public_key: str, signing_algo: str
) -> str:
    """Encrypt message content using model's public key."""
    data = message_content.encode("utf-8")
    if signing_algo == "ecdsa":
        encrypted = encrypt_ecdsa(data, model_public_key)
    elif signing_algo == "ed25519":
        encrypted = encrypt_ed25519(data, model_public_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return encrypted.hex()


def decrypt_message_content(
    encrypted_hex: str, client_private_key, signing_algo: str
) -> str:
    """Decrypt message content using client's private key."""
    encrypted_data = bytes.fromhex(encrypted_hex)
    if signing_algo == "ecdsa":
        decrypted = decrypt_ecdsa(encrypted_data, client_private_key)
    elif signing_algo == "ed25519":
        decrypted = decrypt_ed25519(encrypted_data, client_private_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return decrypted.decode("utf-8")


async def encrypted_streaming_example(model, signing_algo="ecdsa"):
    """Example of encrypted streaming chat completion."""
    # Fetch model public key
    model_pub_key = fetch_model_public_key(model, signing_algo)
    print(f"\n--- Encrypted Streaming Example ({signing_algo.upper()}) ---")
    print(f"Model public key: {model_pub_key[:32]}...")

    # Generate client key pair
    if signing_algo == "ecdsa":
        client_priv_key_hex, client_pub_key_hex, client_priv_key = (
            generate_ecdsa_key_pair()
        )
    else:
        client_priv_key_hex, client_pub_key_hex, client_priv_key = (
            generate_ed25519_key_pair()
        )
    print(f"Client public key: {client_pub_key_hex[:32]}...")

    # Prepare message
    original_content = "Hello, how are you?"
    encrypted_content = encrypt_message_content(
        original_content, model_pub_key, signing_algo
    )

    body = {
        "model": model,
        "messages": [{"role": "user", "content": encrypted_content}],
        "stream": True,
        "max_tokens": 10,
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

    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers=headers,
        data=body_json,
        stream=True,
        timeout=30,
    )

    chat_id = None
    response_text = ""
    decrypted_content = ""

    for chunk in response.iter_lines():
        line = chunk.decode()
        response_text += line + "\n"

        if line.startswith("data: {") and chat_id is None:
            try:
                data = json.loads(line[6:])
                if "id" in data:
                    chat_id = data["id"]
            except:
                pass

        # Try to decrypt content from streaming chunks
        if line.startswith("data: {") and not line.endswith("[DONE]"):
            try:
                data = json.loads(line[6:])
                if "choices" in data and len(data["choices"]) > 0:
                    delta = data["choices"][0].get("delta", {})
                    if "content" in delta:
                        content_hex = delta["content"]
                        try:
                            decrypted_chunk = decrypt_message_content(
                                content_hex, client_priv_key, signing_algo
                            )
                            decrypted_content += decrypted_chunk
                        except:
                            # If decryption fails, might be plain text or invalid hex
                            pass
            except:
                pass

    print(f"Decrypted response: {decrypted_content[:100]}...")

    if chat_id:
        await verify_chat(
            chat_id,
            body_json,
            response_text,
            f"Encrypted Streaming ({signing_algo.upper()})",
            model,
        )


async def encrypted_non_streaming_example(model, signing_algo="ecdsa"):
    """Example of encrypted non-streaming chat completion."""
    # Fetch model public key
    model_pub_key = fetch_model_public_key(model, signing_algo)
    print(f"\n--- Encrypted Non-Streaming Example ({signing_algo.upper()}) ---")
    print(f"Model public key: {model_pub_key[:32]}...")

    # Generate client key pair
    if signing_algo == "ecdsa":
        client_priv_key_hex, client_pub_key_hex, client_priv_key = (
            generate_ecdsa_key_pair()
        )
    else:
        client_priv_key_hex, client_pub_key_hex, client_priv_key = (
            generate_ed25519_key_pair()
        )
    print(f"Client public key: {client_pub_key_hex[:32]}...")

    # Prepare message
    original_content = "Hello, how are you?"
    encrypted_content = encrypt_message_content(
        original_content, model_pub_key, signing_algo
    )

    body = {
        "model": model,
        "messages": [{"role": "user", "content": encrypted_content}],
        "stream": False,
        "max_tokens": 10,
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

    response = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        headers=headers,
        data=body_json,
        timeout=30,
    )

    payload = response.json()
    chat_id = payload["id"]

    # Decrypt response content
    if "choices" in payload and len(payload["choices"]) > 0:
        message = payload["choices"][0].get("message", {})
        if "content" in message:
            encrypted_response = message["content"]
            try:
                decrypted_response = decrypt_message_content(
                    encrypted_response, client_priv_key, signing_algo
                )
                print(f"Decrypted response: {decrypted_response}")
            except Exception as e:
                print(f"Failed to decrypt response: {e}")

    await verify_chat(
        chat_id,
        body_json,
        response.text,
        f"Encrypted Non-Streaming ({signing_algo.upper()})",
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
