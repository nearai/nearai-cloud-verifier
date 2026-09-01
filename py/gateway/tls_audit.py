#!/usr/bin/env python3
"""Verify the TLS identity of the configured NEAR AI Cloud Gateway.

The peer certificate is observed while the Gateway attestation is fetched. A
later TLS connection could reach a different backend, so this utility does not
compare an unrelated follow-up connection or a ``tls_certificate`` copy.
"""

from __future__ import annotations

import asyncio

from py.gateway.cloud_api import (
    API_KEY,
    BASE_URL,
)
from py.gateway.deployment_audit import audit_gateway_attestation


async def main() -> None:
    """Fetch and verify Gateway evidence plus its observed TLS peer."""

    if not API_KEY:
        raise RuntimeError("API_KEY is required to fetch Cloud API Gateway evidence")

    print("========================================")
    print("🔐 Gateway TLS attestation")
    print("========================================")
    print("Gateway endpoint:", BASE_URL)

    await audit_gateway_attestation()


if __name__ == "__main__":
    asyncio.run(main())
