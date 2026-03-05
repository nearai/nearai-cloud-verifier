#!/usr/bin/env python3
"""
TLS Certificate Verification for NEAR AI Inference Proxy

Verifies that an inference proxy's TLS connection terminates inside the TEE
by checking that the live TLS certificate's SPKI hash is bound into the
Intel TDX attestation quote.

How it works:
  1. Connects to the inference proxy and fetches an attestation report with
     `include_tls_fingerprint=true`. This causes the proxy to include its
     TLS certificate's SPKI hash in the TDX report data.
  2. Verifies the Intel TDX quote via dcap-qvl.
  3. Checks that report_data[0..32] = SHA256(signing_address || spki_hash),
     binding the signing key AND the TLS certificate to the TEE.
  4. Connects to the same server via TLS and extracts the live certificate's
     SPKI hash (SHA256 of SubjectPublicKeyInfo DER bytes).
  5. Verifies the live SPKI hash matches the attested tls_cert_fingerprint.

This proves the TLS certificate is held by the TEE — trust comes from the
hardware attestation, not from Certificate Authority trust chains.

Usage:
  python3 py/tls_verifier.py --url https://proxy.example.com:8443
  python3 py/tls_verifier.py --url https://proxy.example.com --signing-algo ed25519
"""

import argparse
import asyncio
import http.client
import json
import os
import secrets
import socket
import ssl
from hashlib import sha256
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from model_verifier import (
    check_tdx_quote,
    check_gpu,
    check_rtmrs,
    show_compose,
    show_sigstore_provenance,
)


def _compute_spki_hash(cert_der: bytes) -> str:
    """Compute SHA-256 of a certificate's SPKI DER encoding.

    Matches the inference proxy's ``compute_spki_hash()`` — hashes the
    SubjectPublicKeyInfo (not the full certificate), making the hash stable
    across certificate renewals that reuse the same key.
    """
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).hexdigest()


def fetch_attestation_and_spki(
    hostname: str,
    port: int,
    nonce: str,
    signing_algo: str = "ecdsa",
    token: str | None = None,
) -> tuple[dict, str]:
    """Fetch attestation report AND extract the live TLS certificate SPKI hash
    from the same connection.

    Using a single TLS connection guarantees both values come from the same
    backend, avoiding mismatches caused by DNS round-robin or load-balancer
    routing between multiple backends.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Trust comes from TEE binding, not CA

    conn = http.client.HTTPSConnection(hostname, port, context=context, timeout=60)
    conn.connect()

    # Extract live SPKI hash from this TLS session
    cert_der = conn.sock.getpeercert(binary_form=True)
    if not cert_der:
        conn.close()
        raise Exception("Failed to get certificate from server")
    live_spki_hash = _compute_spki_hash(cert_der)

    # Make the attestation request over the same connection
    path = (
        f"/v1/attestation/report"
        f"?include_tls_fingerprint=true&nonce={nonce}&signing_algo={signing_algo}"
    )
    headers = {"Host": hostname}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    body = resp.read()
    conn.close()

    if resp.status != 200:
        raise Exception(f"HTTP {resp.status}: {body.decode()}")

    attestation = json.loads(body)
    return attestation, live_spki_hash


def check_report_data_with_tls(
    attestation: dict, request_nonce: str, intel_result: dict
) -> dict:
    """Verify TDX report data binds signing address, TLS fingerprint, and nonce.

    Report data layout (64 bytes):
      [0..32]  = SHA256(signing_address_bytes || cert_fingerprint_bytes)
      [32..64] = nonce
    """
    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = bytes.fromhex(report_data_hex.removeprefix("0x"))
    signing_algo = attestation.get("signing_algo", "ecdsa").lower()

    # Parse signing address bytes
    if signing_algo == "ecdsa":
        signing_address_bytes = bytes.fromhex(
            attestation["signing_address"].removeprefix("0x")
        )
    else:
        signing_address_bytes = bytes.fromhex(attestation["signing_address"])

    embedded_first_32 = report_data[:32]
    embedded_nonce = report_data[32:]

    # Verify first 32 bytes: SHA256(signing_address || cert_fingerprint)
    cert_fp_bytes = bytes.fromhex(attestation["tls_cert_fingerprint"])
    expected = sha256(signing_address_bytes + cert_fp_bytes).digest()

    binds_address_and_tls = embedded_first_32 == expected
    print("Report data binds signing address + TLS fingerprint:", binds_address_and_tls)
    if not binds_address_and_tls:
        print("  expected:", expected.hex())
        print("  actual:  ", embedded_first_32.hex())

    # Verify last 32 bytes: nonce
    embeds_nonce = embedded_nonce.hex() == request_nonce
    print("Report data embeds request nonce:", embeds_nonce)
    if not embeds_nonce:
        print("  expected:", request_nonce)
        print("  actual:  ", embedded_nonce.hex())

    return {
        "binds_address_and_tls": binds_address_and_tls,
        "embeds_nonce": embeds_nonce,
    }


async def verify_tls_attestation(
    url: str, signing_algo: str = "ecdsa", token: str | None = None
) -> None:
    """Main verification: prove a proxy's TLS cert is bound to the TEE."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise Exception("URL must use https:// scheme for TLS verification")

    hostname = parsed.hostname
    port = parsed.port or 443

    # 1. Generate nonce
    request_nonce = secrets.token_hex(32)
    print("Request nonce:", request_nonce)

    # 2. Fetch attestation report AND live SPKI hash from the same TLS connection.
    #    This avoids round-robin mismatches when multiple backends share a domain.
    print(f"\nFetching attestation from {hostname}:{port} (single TLS connection) ...")
    attestation, live_spki_hash = await asyncio.to_thread(
        fetch_attestation_and_spki, hostname, port, request_nonce, signing_algo, token
    )

    tls_cert_fingerprint = attestation.get("tls_cert_fingerprint")
    if not tls_cert_fingerprint:
        raise Exception(
            "Attestation report does not include tls_cert_fingerprint. "
            "The proxy may not have TLS_CERT_PATH configured."
        )

    # Extract model name from attestation (self-reported by the proxy inside the TEE)
    model_name = attestation.get("model_name")
    if model_name:
        print("Model name:", model_name)
    else:
        print("Model name: (not present in attestation)")

    print("Signing address:", attestation["signing_address"])
    print("Signing algorithm:", attestation.get("signing_algo"))
    print("Attested TLS SPKI fingerprint:", tls_cert_fingerprint)

    # 3. Verify Intel TDX quote
    print("\n🔐 Intel TDX quote")
    intel_result = await check_tdx_quote(attestation)

    # 4. Verify report data binds signing address + TLS fingerprint + nonce
    print("\n🔐 TDX report data (TLS mode)")
    check_report_data_with_tls(attestation, request_nonce, intel_result)

    # 5. Compare live certificate SPKI hash (from step 2) with attested fingerprint
    print("\n🔐 Live TLS certificate")
    print("Live certificate SPKI hash:", live_spki_hash)

    tls_match = live_spki_hash == tls_cert_fingerprint
    print("Live SPKI matches attested fingerprint:", tls_match)
    if not tls_match:
        print("  attested:", tls_cert_fingerprint)
        print("  live:    ", live_spki_hash)

    # 6. GPU attestation
    print("\n🔐 GPU attestation")
    check_gpu(attestation, request_nonce)

    # 7. RTMR verification
    print("\n🔐 RTMR verification")
    check_rtmrs(attestation, intel_result)

    # 8. Compose and Sigstore
    show_compose(attestation)
    show_sigstore_provenance(attestation)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify an inference proxy's TLS certificate is bound to the TEE"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="HTTPS URL of the inference proxy (e.g. https://proxy.example.com:8443)",
    )
    parser.add_argument(
        "--signing-algo",
        default="ecdsa",
        choices=["ecdsa", "ed25519"],
        help="Signing algorithm (default: ecdsa)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("API_KEY"),
        help="Bearer token for proxies that require auth (default: API_KEY env var)",
    )
    args = parser.parse_args()

    print("========================================")
    print("🔐 TLS Attestation Verification")
    print("========================================")
    print(f"Target: {args.url}")
    print(f"Signing algorithm: {args.signing_algo}")

    await verify_tls_attestation(args.url, args.signing_algo, args.token)


if __name__ == "__main__":
    asyncio.run(main())
