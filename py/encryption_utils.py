"""Shared helpers for NEAR AI Cloud E2E encryption demos (Python).

This module is used by both:
- encrypted_chat_verifier.py
- encrypted_image_verifier.py
"""

from __future__ import annotations

import secrets

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings
from nacl.public import Box, PrivateKey as X25519PrivateKeyNaCl, PublicKey as X25519PublicKeyNaCl


def fetch_model_public_key(
    *,
    base_url: str,
    api_key: str,
    model: str,
    signing_algo: str = "ecdsa",
) -> str:
    """Fetch model public key from attestation report."""
    url = f"{base_url}/v1/attestation/report?model={model}&signing_algo={signing_algo}"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    report = requests.get(url, headers=headers, timeout=30).json()

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

    private_numbers = private_key.private_numbers()
    private_key_int = private_numbers.private_value
    private_key_bytes = private_key_int.to_bytes(32, byteorder="big")

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    public_key_hex = public_key_bytes[1:].hex()  # drop 0x04 prefix
    private_key_hex = private_key_bytes.hex()

    return private_key_hex, public_key_hex, private_key


def generate_ed25519_key_pair():
    """Generate Ed25519 key pair and return (private_key_hex, public_key_hex, private_key_obj)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return private_key_bytes.hex(), public_key_bytes.hex(), private_key


def encrypt_ecdsa(data: bytes, public_key_hex: str) -> bytes:
    """Encrypt data using ECDSA public key (ECIES)."""
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) == 65 and public_key_bytes[0] == 0x04:
        public_key_bytes = public_key_bytes[1:]

    if len(public_key_bytes) != 64:
        raise ValueError(f"ECDSA public key must be 64 bytes, got {len(public_key_bytes)}")

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x04" + public_key_bytes
    )

    ephemeral_private = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdsa_encryption",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return ephemeral_public_bytes + nonce + ciphertext


def decrypt_ecdsa(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt data using ECDSA private key."""
    if len(encrypted_data) < 93:
        raise ValueError("Encrypted data too short")

    ephemeral_public_bytes = encrypted_data[:65]
    nonce = encrypted_data[65:77]
    ciphertext = encrypted_data[77:]

    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), ephemeral_public_bytes
    )

    shared_secret = private_key_obj.exchange(ec.ECDH(), ephemeral_public)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdsa_encryption",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(shared_secret)

    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_ed25519(data: bytes, public_key_hex: str) -> bytes:
    """Encrypt data using Ed25519 public key via PyNaCl Box."""
    public_key_bytes = bytes.fromhex(public_key_hex)
    if len(public_key_bytes) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key_bytes)}")

    x25519_public = X25519PublicKeyNaCl(
        bindings.crypto_sign_ed25519_pk_to_curve25519(public_key_bytes)
    )

    ephemeral_private = X25519PrivateKeyNaCl.generate()
    ephemeral_public = ephemeral_private.public_key  # property (not method)

    box = Box(ephemeral_private, x25519_public)
    encrypted = box.encrypt(data)

    ephemeral_public_bytes = bytes(ephemeral_public)
    return ephemeral_public_bytes + encrypted


def decrypt_ed25519(encrypted_data: bytes, private_key_obj) -> bytes:
    """Decrypt data using Ed25519 private key via PyNaCl Box."""
    if len(encrypted_data) < 72:
        raise ValueError("Encrypted data too short")

    ephemeral_public_bytes = encrypted_data[:32]
    box_encrypted = encrypted_data[32:]

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
    x25519_private_bytes = bindings.crypto_sign_ed25519_sk_to_curve25519(ed25519_secret_key)
    x25519_private = X25519PrivateKeyNaCl(x25519_private_bytes)

    ephemeral_public = X25519PublicKeyNaCl(ephemeral_public_bytes)
    box = Box(x25519_private, ephemeral_public)
    return box.decrypt(box_encrypted)


def encrypt_text(text: str, model_public_key: str, signing_algo: str) -> str:
    data = text.encode("utf-8")
    if signing_algo == "ecdsa":
        encrypted = encrypt_ecdsa(data, model_public_key)
    elif signing_algo == "ed25519":
        encrypted = encrypt_ed25519(data, model_public_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return encrypted.hex()


def decrypt_text(encrypted_hex: str, client_private_key, signing_algo: str) -> str:
    encrypted_data = bytes.fromhex(encrypted_hex)
    if signing_algo == "ecdsa":
        decrypted = decrypt_ecdsa(encrypted_data, client_private_key)
    elif signing_algo == "ed25519":
        decrypted = decrypt_ed25519(encrypted_data, client_private_key)
    else:
        raise ValueError(f"Unsupported signing algorithm: {signing_algo}")
    return decrypted.decode("utf-8")

