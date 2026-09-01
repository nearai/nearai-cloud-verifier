#!/usr/bin/env python3
"""
Direct Model Attestation Verification for a NEAR AI Model Endpoint

Verifies that a model-serving endpoint's TLS connection terminates inside the TEE
by checking that the live TLS certificate's SPKI hash is bound into the
Intel TDX attestation quote.

How it works:
  1. Connects to the model endpoint and fetches an attestation report with
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
  python3 -m py.direct_model_attestation --url https://your-model.completions.near.ai
  python3 -m py.direct_model_attestation --url https://your-model.completions.near.ai --signing-algo ed25519
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import json
import os
import secrets
import ssl
from hashlib import sha256
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from py.utils.attestation import (
    verify_dstack_quote,
    verify_nvidia_evidence,
    decode_hex,
    verify_dstack_deployment,
    verify_attestation_nonce,
    verify_report_data_binding_with_tls_fingerprint,
)


def _compute_spki_hash(cert_der: bytes) -> str:
    """Compute SHA-256 of a certificate's SPKI DER encoding.

    Matches the model endpoint's ``compute_spki_hash()`` — hashes the
    SubjectPublicKeyInfo (not the full certificate), making the hash stable
    across certificate renewals that reuse the same key.
    """
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    spki_der = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).hexdigest()


def fetch_model_attestation_and_spki(
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
    try:
        conn.connect()
        socket = conn.sock
        if socket is None:
            raise RuntimeError("TLS connection did not expose a socket")

        # Extract the certificate before sending the evidence request, from
        # this same TLS connection that will serve the response.
        cert_der = socket.getpeercert(binary_form=True)
        if not cert_der:
            raise RuntimeError("Failed to get certificate from server")
        live_spki_hash = _compute_spki_hash(cert_der)

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
    finally:
        conn.close()

    if resp.status != 200:
        raise Exception(f"HTTP {resp.status}: {body.decode()}")

    attestation = json.loads(body)
    if not isinstance(attestation, dict):
        raise ValueError("Attestation endpoint returned a non-object JSON value")
    return attestation, live_spki_hash


async def verify_direct_model_attestation(
    url: str, signing_algo: str = "ecdsa", token: str | None = None
) -> None:
    """Verify a direct model attestation and its endpoint TLS binding."""
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
        fetch_model_attestation_and_spki,
        hostname,
        port,
        request_nonce,
        signing_algo,
        token,
    )
    if not verify_attestation_nonce(attestation, request_nonce):
        raise RuntimeError(
            "Attestation request_nonce does not match the nonce sent by this verifier"
        )

    tls_cert_fingerprint = attestation.get("tls_cert_fingerprint")
    if not tls_cert_fingerprint:
        raise Exception(
            "Attestation report does not include tls_cert_fingerprint. "
            "The model endpoint may not be configured to expose a TLS certificate fingerprint."
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
    intel_result = await verify_dstack_quote(attestation)
    if intel_result is None or intel_result.get("verified") is not True:
        raise RuntimeError("Intel TDX quote did not verify with an accepted TCB status")
    if intel_result.get("debug_enabled") is not False:
        raise RuntimeError("Intel TDX quote enables debug mode")

    # 4. Verify report data binds signing address + TLS fingerprint + nonce
    print("\n🔐 TDX report data (TLS mode)")
    report_data = verify_report_data_binding_with_tls_fingerprint(
        attestation,
        request_nonce,
        intel_result,
    )
    if not report_data["report_data_matches_quote"]:
        raise RuntimeError(
            "Attestation report_data does not match report_data in the verified quote"
        )
    if not report_data["binds_signer"] or not report_data["embeds_nonce"]:
        raise RuntimeError(
            "Quote report_data does not bind the signer, TLS fingerprint, and nonce"
        )

    # 5. Compare live certificate SPKI hash (from step 2) with attested fingerprint
    print("\n🔐 Live TLS certificate")
    print("Live certificate SPKI hash:", live_spki_hash)

    tls_match = decode_hex(
        live_spki_hash,
        "live TLS certificate SPKI fingerprint",
    ) == decode_hex(
        tls_cert_fingerprint,
        "attestation.tls_cert_fingerprint",
    )
    print("Live SPKI matches attested fingerprint:", tls_match)
    if not tls_match:
        print("  attested:", tls_cert_fingerprint)
        print("  live:    ", live_spki_hash)
        raise RuntimeError("Live TLS SPKI fingerprint does not match the attestation")

    # 6. GPU attestation
    print("\n🔐 GPU attestation")
    if attestation.get("nvidia_payload"):
        gpu = verify_nvidia_evidence(attestation, request_nonce)
        if gpu.get("verified") is not True:
            raise RuntimeError("Provided NVIDIA GPU evidence did not verify")
    else:
        print("No nvidia_payload in attestation; skipping GPU check.")

    # 7. Measured deployment
    deployment = verify_dstack_deployment(attestation, intel_result)
    if deployment["event_log"].get("replay_matches") is not True:
        raise RuntimeError("Event log does not replay to RTMR3 from the verified quote")
    if deployment["compose"].get("mrconfig_matches") is not True:
        raise RuntimeError("MRCONFIGID does not bind the attested app_compose")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a direct model attestation and its TLS binding"
    )
    parser.add_argument(
        "--url",
        required=True,
        help="HTTPS URL of the model endpoint (e.g. https://your-model.completions.near.ai)",
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
    print("🔐 Direct model attestation verification")
    print("========================================")
    print(f"Target: {args.url}")
    print(f"Signing algorithm: {args.signing_algo}")

    await verify_direct_model_attestation(args.url, args.signing_algo, args.token)


if __name__ == "__main__":
    asyncio.run(main())
