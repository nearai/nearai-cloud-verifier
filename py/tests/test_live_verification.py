"""End-to-end verification against real services.

Two opt-in tiers:

- ``@pytest.mark.integration`` — re-verifies the captured golden fixture against
  real Intel PCCS and NVIDIA NRAS. Reproducible but drifts as TCB collateral
  rotates (~monthly); recapture the fixture when it starts failing.

- ``@pytest.mark.live`` — fetches a fresh report from ``cloud-api.near.ai``
  with a random nonce and runs the full ``verify_report``. This is the
  canonical end-to-end: it exercises the exact code path a user would.

Both are excluded from the default ``pytest`` run via
``-m "not integration and not live"`` in CI.
"""
import os
import secrets

import pytest

import model_verifier as mv


@pytest.mark.integration
class TestVerifyFixtureAgainstRealServices:
    async def test_golden_fixture_verifies_end_to_end(self, golden_report, golden_nonce):
        requested = golden_report["model_attestations"][0]["model_name"]
        results = await mv.verify_report(golden_report, golden_nonce, requested_model=requested)

        for name, r in results:
            assert r.valid, f"{name} failed: {r}"


@pytest.mark.live
class TestLiveVerification:
    """Exercises the real client flow: fresh nonce → fetch → verify.

    Skipped when ``cloud-api.near.ai`` is unreachable. The fetched model
    defaults to the upstream README's default (DeepSeek-V3.1) but can be
    overridden via ``NEARAI_TEST_MODEL``.

    Note: the gateway's routing may return an attestation whose
    ``model_name`` differs from the requested model (observed in practice:
    DeepSeek-V3.1 → Qwen3.5-122B-A10B). ``verify_report``'s
    ``requested_model`` check catches this — but for a stable CI signal
    this test verifies against whatever ``model_name`` the gateway
    actually returns. The requested-model mismatch path is covered by
    ``test_verify_attestation.TestVerifyReport`` with stubbed inputs.
    """

    async def test_fresh_fetch_and_verify(self):
        model = os.environ.get("NEARAI_TEST_MODEL", "deepseek-ai/DeepSeek-V3.1")
        nonce = secrets.token_hex(32)

        try:
            report = mv.fetch_report(model, nonce)
        except Exception as e:
            pytest.skip(f"cloud-api.near.ai unreachable: {e}")

        served = report["model_attestations"][0].get("model_name", model)
        results = await mv.verify_report(report, nonce, requested_model=served)

        for name, r in results:
            assert r.valid, f"{name} failed: {r}"
