"""Tests for the new ``VerificationResult``, ``show_compose`` return value,
and the orchestration logic in ``verify_report``.

Network-dependent primitives (``check_tdx_quote`` via ``dcap_qvl``, ``check_gpu``
via NRAS) are stubbed via ``monkeypatch`` so the tests remain offline.
"""
import hashlib
import json

import pytest

import model_verifier as mv


# ---------------------------------------------------------------------------
# Helpers to build a stubbed intel_result consistent with an attestation
# ---------------------------------------------------------------------------

def _mrconfig_for(app_compose: str) -> str:
    """mr_config as the enclave would produce it from a given compose blob."""
    # "01" prefix + 32-byte sha256 + 15 bytes of zero padding (48 bytes total in
    # the real quote; we only need it to start with "01"+hash for the check).
    return "01" + hashlib.sha256(app_compose.encode()).hexdigest() + ("00" * 15)


def _intel_result_for(attestation: dict, verified: bool = True) -> dict:
    """Build a stubbed intel_result that's consistent with ``attestation``."""
    tcb = mv._parsed_tcb_info(attestation) or {}
    app_compose = tcb.get("app_compose", "")
    # gateway attestations have top-level report_data; model attestations don't,
    # so synthesize one from signing_address + request_nonce in ecdsa mode.
    rd = attestation.get("report_data")
    if not rd:
        addr = attestation["signing_address"].removeprefix("0x")
        nonce = attestation["request_nonce"]
        rd = (addr + "00" * 12 + nonce)
    return {
        "quote": {"body": {"reportdata": rd, "mrconfig": _mrconfig_for(app_compose)}},
        "verified": verified,
        "status": "UpToDate" if verified else "InvalidSignature",
        "advisory_ids": [],
    }


@pytest.fixture
def nras_verdict_true(monkeypatch):
    """Make ``check_gpu`` think NRAS returned overall-att-result=True."""
    def _fake(payload):
        import base64
        inner = json.dumps({"x-nvidia-overall-att-result": True}).encode()
        encoded = base64.urlsafe_b64encode(inner).rstrip(b"=").decode()
        jwt = f"h.{encoded}.s"
        return [[None, jwt]]
    monkeypatch.setattr(mv, "fetch_nvidia_verification", _fake)


# ---------------------------------------------------------------------------
# VerificationResult.valid truth table
# ---------------------------------------------------------------------------

class TestVerificationResultValid:
    def test_all_true_is_valid(self):
        r = mv.VerificationResult(
            tdx_verified=True, binds_address=True, embeds_nonce=True, compose_match=True, gpu_ok=True,
        )
        assert r.valid is True

    def test_any_core_check_false_is_invalid(self):
        base = dict(tdx_verified=True, binds_address=True, embeds_nonce=True, compose_match=True)
        for flip in ("tdx_verified", "binds_address", "embeds_nonce", "compose_match"):
            bad = dict(base, **{flip: False})
            assert mv.VerificationResult(**bad).valid is False, f"expected invalid when {flip}=False"

    def test_gpu_none_is_skipped_not_failed(self):
        """gpu_ok=None means 'not requested' (gateway-only mode) — should not fail the verdict."""
        r = mv.VerificationResult(tdx_verified=True, binds_address=True, embeds_nonce=True, compose_match=True, gpu_ok=None)
        assert r.valid is True

    def test_gpu_false_fails_even_when_tdx_ok(self):
        r = mv.VerificationResult(tdx_verified=True, binds_address=True, embeds_nonce=True, compose_match=True, gpu_ok=False)
        assert r.valid is False


# ---------------------------------------------------------------------------
# show_compose now returns a bool
# ---------------------------------------------------------------------------

class TestShowComposeReturn:
    def test_returns_true_when_mrconfig_matches(self, golden_gateway):
        intel_result = _intel_result_for(golden_gateway)
        assert mv.show_compose(golden_gateway, intel_result) is True

    def test_returns_false_when_mrconfig_mismatches(self, golden_gateway):
        intel_result = _intel_result_for(golden_gateway)
        intel_result["quote"]["body"]["mrconfig"] = "01" + "ff" * 47  # bogus hash
        assert mv.show_compose(golden_gateway, intel_result) is False

    def test_returns_true_when_no_compose_is_attested(self):
        """No app_compose means there's nothing to verify — not a failure."""
        intel_result = {"quote": {"body": {"reportdata": "", "mrconfig": "00" * 48}}}
        assert mv.show_compose({}, intel_result) is True


# ---------------------------------------------------------------------------
# verify_attestation returns a VerificationResult
# ---------------------------------------------------------------------------

class TestVerifyAttestationReturnsResult:
    @pytest.mark.asyncio
    async def test_happy_path_returns_valid_result(self, monkeypatch, golden_gateway, golden_nonce):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        result = await mv.verify_attestation(golden_gateway, golden_nonce, verify_model=False)
        assert isinstance(result, mv.VerificationResult)
        assert result.tdx_verified is True
        assert result.binds_address is True
        assert result.embeds_nonce is True
        assert result.compose_match is True
        assert result.gpu_ok is None  # not requested
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_wrong_nonce_flips_embeds_nonce_and_invalidates(self, monkeypatch, golden_gateway):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        result = await mv.verify_attestation(golden_gateway, "00" * 32, verify_model=False)
        assert result.embeds_nonce is False
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_compose_mismatch_invalidates(self, monkeypatch, golden_gateway, golden_nonce):
        async def fake_tdx(att):
            ir = _intel_result_for(att)
            ir["quote"]["body"]["mrconfig"] = "01" + "ab" * 47  # mismatched
            return ir
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        result = await mv.verify_attestation(golden_gateway, golden_nonce, verify_model=False)
        assert result.compose_match is False
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_tdx_unverified_short_circuits(self, monkeypatch, golden_gateway, golden_nonce):
        async def fake_tdx(att):
            return None  # simulates check_tdx_quote swallowing a ValueError
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        result = await mv.verify_attestation(golden_gateway, golden_nonce, verify_model=False)
        assert result.tdx_verified is False
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_verify_model_runs_gpu_check(self, monkeypatch, golden_model, golden_nonce, nras_verdict_true):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        result = await mv.verify_attestation(golden_model, golden_nonce, verify_model=True)
        assert result.gpu_ok is True
        assert result.valid is True

    @pytest.mark.asyncio
    async def test_gpu_verdict_false_invalidates(self, monkeypatch, golden_model, golden_nonce):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        def fake_nvidia_false(payload):
            import base64
            inner = json.dumps({"x-nvidia-overall-att-result": False}).encode()
            encoded = base64.urlsafe_b64encode(inner).rstrip(b"=").decode()
            return [[None, f"h.{encoded}.s"]]
        monkeypatch.setattr(mv, "fetch_nvidia_verification", fake_nvidia_false)

        result = await mv.verify_attestation(golden_model, golden_nonce, verify_model=True)
        assert result.gpu_ok is False
        assert result.valid is False


# ---------------------------------------------------------------------------
# verify_report: enforces empty-list + requested-model-matches
# ---------------------------------------------------------------------------

class TestVerifyReport:
    @pytest.mark.asyncio
    async def test_empty_model_attestations_produces_failure(self, golden_gateway, golden_nonce, monkeypatch):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        report = {"gateway_attestation": golden_gateway, "model_attestations": []}
        results = await mv.verify_report(report, golden_nonce, requested_model="anything")

        # gateway still verifies; but the absence of model attestations is recorded as a failure
        labels = {name for name, _ in results}
        assert "model_attestations_present" in labels
        assert any(not r.valid for _, r in results)

    @pytest.mark.asyncio
    async def test_requested_model_mismatch_produces_failure(self, golden_gateway, golden_model, golden_nonce, monkeypatch):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        report = {"gateway_attestation": golden_gateway, "model_attestations": [golden_model]}
        # golden_model's model_name is 'openai/gpt-oss-120b'; ask for something else
        results = await mv.verify_report(report, golden_nonce, requested_model="openai/DIFFERENT-model")

        mismatch_labels = [name for name, _ in results if "requested_model" in name]
        assert mismatch_labels, "expected a requested_model failure entry"
        assert any(not r.valid for _, r in results)

    @pytest.mark.asyncio
    async def test_happy_path_all_valid(self, golden_gateway, golden_model, golden_nonce, monkeypatch, nras_verdict_true):
        async def fake_tdx(att):
            return _intel_result_for(att)
        monkeypatch.setattr(mv, "check_tdx_quote", fake_tdx)

        report = {"gateway_attestation": golden_gateway, "model_attestations": [golden_model]}
        requested = golden_model["model_name"]
        results = await mv.verify_report(report, golden_nonce, requested_model=requested)

        assert all(r.valid for _, r in results), f"failures: {[(n, r) for n, r in results if not r.valid]}"
