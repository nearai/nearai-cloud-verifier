#!/usr/bin/env python3
"""Test end-to-end encryption for NEAR AI Cloud chat completions."""

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
from nacl import bindings

from py.completion import verify_completion

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")
MAX_TOKENS = 100


def cloud_api_url(path: str) -> str:
    """Build a Cloud API URL whether BASE_URL includes /v1 or not."""

    base = BASE_URL.rstrip("/")
    prefix = base if base.endswith("/v1") else f"{base}/v1"
    return f"{prefix}/{path.lstrip('/')}"


def fetch_model_public_key(model, signing_algo="ecdsa"):
    """Fetch the NEAR model public key without aliasing or TLS binding."""

    response = requests.get(
        cloud_api_url("attestation/report"),
        params={
            "model": model,
            "provider": "near",
            "nonce": secrets.token_hex(32),
            "signing_algo": signing_algo,
            "include_tls_fingerprint": "false",
        },
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "x-no-aliasing": "true",
        },
        timeout=30,
    )
    response.raise_for_status()
    report = response.json()

    if isinstance(report, dict) and isinstance(report.get("model_attestations"), list):
        for attestation in report["model_attestations"]:
            if isinstance(attestation, dict) and isinstance(
                attestation.get("signing_public_key"), str
            ):
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


def ed25519_v2_key(shared_secret: bytes) -> bytes:
    """Derive the v2 E2EE key from an X25519 shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ed25519_encryption",
        backend=default_backend(),
    ).derive(shared_secret)


def encrypt_ed25519(data: bytes, public_key_hex: str) -> bytes:
    """Encrypt data with the Ed25519 E2EE v2 protocol.

    The protocol converts the recipient key to X25519, then uses X25519 ECDH,
    HKDF-SHA256, and XChaCha20-Poly1305. Its wire format is
    ``[ephemeral public key][nonce][ciphertext + tag]``.
    """
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}"
        )

    recipient_x25519_public = bindings.crypto_sign_ed25519_pk_to_curve25519(
        public_key_bytes
    )
    ephemeral_private = secrets.token_bytes(32)
    ephemeral_public = bindings.crypto_scalarmult_base(ephemeral_private)
    shared_secret = bindings.crypto_scalarmult(
        ephemeral_private, recipient_x25519_public
    )
    nonce = secrets.token_bytes(
        bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    )
    ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        data, None, nonce, ed25519_v2_key(shared_secret)
    )
    return ephemeral_public + nonce + ciphertext


def decrypt_ed25519(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt data with the Ed25519 E2EE v2 protocol."""
    if len(encrypted_data) < 72:
        raise ValueError("Encrypted data too short")

    ephemeral_public_bytes = encrypted_data[:32]
    nonce = encrypted_data[32:56]
    ciphertext = encrypted_data[56:]

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
    shared_secret = bindings.crypto_scalarmult(
        x25519_private_bytes, ephemeral_public_bytes
    )
    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext, None, nonce, ed25519_v2_key(shared_secret)
    )


def encryption_version_header(signing_algo: str) -> dict[str, str]:
    """Request the current Ed25519 encryption protocol when it is in use."""
    return {"X-Encryption-Version": "2"} if signing_algo == "ed25519" else {}


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
    request_body = json.dumps(body, separators=(",", ":")).encode("utf-8")

    # Make request with encryption headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Signing-Algo": signing_algo,
        "X-Client-Pub-Key": client_pub_key_hex,
        "X-Model-Pub-Key": model_pub_key,
        "Accept-Encoding": "identity",
        "x-no-aliasing": "true",
        **encryption_version_header(signing_algo),
    }

    try:
        response = requests.post(
            cloud_api_url("chat/completions"),
            headers=headers,
            data=request_body,
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
    decrypted_content = ""
    decryption_failures = []

    print("\nReceiving stream...")
    response_body = b"".join(response.iter_content(chunk_size=None))
    for raw_line in response_body.splitlines():
        line = raw_line.decode("utf-8")

        if line.startswith("data: {") and chat_id is None:
            try:
                data = json.loads(line[6:])
                if "id" in data:
                    chat_id = data["id"]
                    print(f"✓ Chat ID: {chat_id}")
            except Exception as e:
                print(f"✗ Failed to parse chat ID: {e}")
                print(f"  Line: {line}")

        # Content and reasoning fields are independently encrypted in each
        # streaming event.
        if line.startswith("data: {") and not line.endswith("[DONE]"):
            try:
                data = json.loads(line[6:])
                if "choices" in data and len(data["choices"]) > 0:
                    delta = data["choices"][0].get("delta", {})
                    for field in ["content", "reasoning_content", "reasoning"]:
                        encrypted_value = delta.get(field)
                        if isinstance(encrypted_value, str) and encrypted_value:
                            try:
                                decrypted_chunk = decrypt_message_content(
                                    encrypted_value, client_priv_key, signing_algo
                                )
                                if field == "content":
                                    decrypted_content += decrypted_chunk
                                print(
                                    f"  Decrypted {field} chunk: {decrypted_chunk}\n",
                                    end="",
                                    flush=True,
                                )
                            except Exception as e:
                                print(f"✗ Failed to decrypt {field}: {e}")
                                decryption_failures.append(f"{field}: {e}")
            except Exception as e:
                print(f"✗ Failed to parse encrypted stream event: {e}")

    print(f"\n\n✓ Complete decrypted response: {decrypted_content}")
    print(f"✓ Total response length: {len(response_body)} bytes")
    if chat_id is None:
        raise ValueError("Streaming response did not contain a completion id")
    await verify_completion(
        chat_id,
        request_body,
        response_body,
        f"Verifying Encrypted Streaming ({signing_algo.upper()})",
        signing_algo=signing_algo,
    )
    if decryption_failures:
        raise RuntimeError(
            "Could not decrypt encrypted stream fields: "
            + "; ".join(decryption_failures)
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
    request_body = json.dumps(body, separators=(",", ":")).encode("utf-8")

    # Make request with encryption headers
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}",
        "X-Signing-Algo": signing_algo,
        "X-Client-Pub-Key": client_pub_key_hex,
        "X-Model-Pub-Key": model_pub_key,
        "Accept-Encoding": "identity",
        "x-no-aliasing": "true",
        **encryption_version_header(signing_algo),
    }

    try:
        response = requests.post(
            cloud_api_url("chat/completions"),
            headers=headers,
            data=request_body,
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

    response_body = response.content
    payload = json.loads(response_body)
    chat_id = payload.get("id") if isinstance(payload, dict) else None
    if not isinstance(chat_id, str):
        raise ValueError("Non-streaming response did not contain a completion id")
    print(f"✓ Chat ID: {chat_id}")

    # Check finish_reason to see if response was truncated
    if "choices" in payload and len(payload["choices"]) > 0:
        choice = payload["choices"][0]
        finish_reason = choice.get("finish_reason", "unknown")
        print(f"✓ Finish reason: {finish_reason}")
        if finish_reason == "length":
            print("  ⚠ Response was truncated due to max_tokens limit")

    decryption_failures = []

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
                            decryption_failures.append(f"{field}: {e}")
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
                print("\n⚠ No content field found in decrypted fields")
        else:
            print("\n⚠ No encrypted fields found to decrypt")
            print(f"  Message keys: {list(message.keys())}")
            print(f"  Message: {json.dumps(message, indent=2)}")
    else:
        print("✗ No choices in response")
        print(f"  Response: {json.dumps(payload, indent=2)}")

    await verify_completion(
        chat_id,
        request_body,
        response_body,
        f"Verifying Encrypted Non-Streaming ({signing_algo.upper()})",
        signing_algo=signing_algo,
    )
    if decryption_failures:
        raise RuntimeError(
            "Could not decrypt encrypted response fields: "
            + "; ".join(decryption_failures)
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
