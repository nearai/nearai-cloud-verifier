#!/usr/bin/env python3
"""Independently audit Cloud API Gateway and model-serving deployments.

This command accepts no completion signature or response bytes. It verifies
fresh deployment evidence but cannot associate either attestation with a chat.
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Optional, Sequence

from py.common.dstack_attestation import SUPPORTED_SIGNING_ALGOS
from py.gateway.cloud_api import (
    API_KEY,
    fetch_gateway_attestation,
    fetch_model_attestations,
)
from py.gateway.attestation import (
    VerifiedGatewayAttestation,
    VerifiedModelAttestation,
    verify_gateway_attestation,
    verify_model_attestation,
)


async def audit_gateway_attestation(
    signing_algo: Optional[str] = None,
) -> VerifiedGatewayAttestation:
    """Fetch and independently audit Gateway evidence, without a completion."""

    attestation, nonce, peer_spki = fetch_gateway_attestation(signing_algo=signing_algo)
    return await verify_gateway_attestation(attestation, nonce, peer_spki)


async def audit_model_attestations(
    model: str, signing_algo: Optional[str] = None
) -> Sequence[VerifiedModelAttestation]:
    """Fetch and independently audit model evidence, without a completion."""

    attestations, nonce = fetch_model_attestations(model, signing_algo=signing_algo)
    verified: list[VerifiedModelAttestation] = []
    for index, attestation in enumerate(attestations, start=1):
        print(
            f"\n========================================\n"
            f"Model attestation {index}\n"
            f"========================================"
        )
        verified.append(await verify_model_attestation(attestation, nonce))
    return verified


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit NEAR AI Cloud Gateway and model attestations"
    )
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument(
        "--signing-algo",
        choices=sorted(SUPPORTED_SIGNING_ALGOS),
        help="Request a specific algorithm; omit to use the Cloud API default.",
    )
    args = parser.parse_args()

    if not API_KEY:
        raise RuntimeError("API_KEY is required to fetch Cloud API attestations")

    print("========================================")
    print("NEAR AI Cloud Gateway deployment audit")
    print("========================================")
    await audit_gateway_attestation(args.signing_algo)
    await audit_model_attestations(args.model, args.signing_algo)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
