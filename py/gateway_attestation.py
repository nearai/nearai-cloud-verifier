#!/usr/bin/env python3
"""Fetch and verify NEAR AI Cloud Gateway-attestation evidence.

The TLS peer certificate is observed while the Gateway attestation is fetched.
A later TLS connection could reach a different backend, so this example does
not compare an unrelated follow-up connection or a ``tls_certificate`` copy.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets

from py.utils.attestation import SUPPORTED_SIGNING_ALGOS
from py.utils.api import (
    API_KEY,
    BASE_URL,
    fetch_gateway_attestation,
)
from py.utils.verifier import (
    verify_gateway_attestation,
)


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify NEAR AI Cloud Gateway attestation evidence"
    )
    parser.add_argument(
        "--signing-algo",
        choices=sorted(SUPPORTED_SIGNING_ALGOS),
        help="Request a specific algorithm; omit to use the Cloud API default.",
    )
    args = parser.parse_args()

    if not API_KEY:
        raise RuntimeError("API_KEY is required to fetch Cloud API Gateway evidence")

    print("========================================")
    print("🔐 NEAR AI Cloud Gateway attestation")
    print("========================================")
    print("Gateway endpoint:", BASE_URL)

    nonce = secrets.token_hex(32)
    attestation, peer_spki = fetch_gateway_attestation(
        nonce, signing_algo=args.signing_algo
    )
    await verify_gateway_attestation(attestation, nonce, peer_spki)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
