"""Pytest fixtures for the verifier test suite.

The golden bundle in ``fixtures/`` was captured from::

    curl "https://cloud-api.near.ai/v1/attestation/report?model=openai/gpt-oss-120b&nonce=<N>&signing_algo=ecdsa"

with ``nonce = "deadbeef" + "0"*56``. It is a real, network-served response — used
for tests that exercise parsing and pure helper logic without re-running TDX or
NRAS verification.
"""
import json
import sys
from pathlib import Path

import pytest

_FIXTURES = Path(__file__).parent / "fixtures"

# Make py/ importable as a package root so tests can do ``import model_verifier``.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="session")
def golden_report():
    """Full attestation report as returned by /v1/attestation/report."""
    with open(_FIXTURES / "nearai_cloud_report_openai_gpt_oss_120b.json") as f:
        return json.load(f)


@pytest.fixture(scope="session")
def golden_gateway(golden_report):
    return golden_report["gateway_attestation"]


@pytest.fixture(scope="session")
def golden_model(golden_report):
    return golden_report["model_attestations"][0]


@pytest.fixture(scope="session")
def golden_nonce():
    """The nonce the fixture was captured with."""
    return "deadbeef" + "0" * 55 + "1"
