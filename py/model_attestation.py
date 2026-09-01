#!/usr/bin/env python3
"""Fetch and verify NEAR AI Cloud model-attestation evidence.

This command verifies the model-serving deployment selected by ``--model``. It
does not verify a completion signature or associate the attestation with a
particular chat response; use ``completion`` for that flow.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets

from py.utils.attestation import SUPPORTED_SIGNING_ALGOS
from py.utils.api import (
    API_KEY,
    fetch_model_attestations,
)
from py.utils.verifier import (
    verify_model_attestation,
)


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify NEAR AI Cloud model attestation evidence"
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
    print("NEAR AI Cloud model attestation")
    print("========================================")
    print("Model:", args.model)

    nonce = secrets.token_hex(32)
    attestations = fetch_model_attestations(
        args.model, nonce, signing_algo=args.signing_algo
    )
    for index, attestation in enumerate(attestations, start=1):
        print(
            f"\n========================================\n"
            f"Model attestation {index}\n"
            f"========================================"
        )
        await verify_model_attestation(attestation, nonce)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
