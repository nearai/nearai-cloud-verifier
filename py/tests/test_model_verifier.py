"""Unit tests for pure helpers in ``model_verifier.py``.

These tests deliberately avoid hitting the network: TDX quote verification
(``check_tdx_quote`` → ``dcap_qvl``) and GPU attestation (``check_gpu`` → NRAS)
are not exercised here. They cover the deterministic helpers that parse
report bundles, extract provenance links, and validate ``report_data`` binding.

The golden fixture in ``fixtures/`` was captured from a real call to
``cloud-api.near.ai``; see ``conftest.py`` for the capture command.
"""
import json

import pytest

import model_verifier as mv


# ---------------------------------------------------------------------------
# _signing_address_padded32
# ---------------------------------------------------------------------------

class TestSigningAddressPadded32:
    def test_ecdsa_strips_0x_and_right_pads_to_32(self):
        addr = "0x" + "ab" * 20  # 20-byte eth address
        out = mv._signing_address_padded32(addr, "ecdsa")
        assert len(out) == 32
        assert out[:20] == bytes.fromhex("ab" * 20)
        assert out[20:] == b"\x00" * 12

    def test_ed25519_does_not_strip_0x_prefix(self):
        # ed25519 addresses are raw hex (no 0x). Feed a 32-byte hex string.
        addr = "cd" * 32
        out = mv._signing_address_padded32(addr, "ed25519")
        assert len(out) == 32
        assert out == bytes.fromhex(addr)

    def test_raises_when_address_exceeds_32_bytes(self):
        with pytest.raises(ValueError, match="too long"):
            mv._signing_address_padded32("ab" * 33, "ed25519")


# ---------------------------------------------------------------------------
# _report_data_bytes
# ---------------------------------------------------------------------------

class TestReportDataBytes:
    def test_strips_0x_prefix(self):
        intel_result = {"quote": {"body": {"reportdata": "0x" + "ff" * 64}}}
        out = mv._report_data_bytes(intel_result)
        assert out == b"\xff" * 64

    def test_accepts_unprefixed_hex(self):
        intel_result = {"quote": {"body": {"reportdata": "00" * 64}}}
        out = mv._report_data_bytes(intel_result)
        assert out == b"\x00" * 64


# ---------------------------------------------------------------------------
# extract_sigstore_links
# ---------------------------------------------------------------------------

class TestExtractSigstoreLinks:
    def test_extracts_sha256_digests(self):
        compose = (
            "services:\n"
            "  app:\n"
            "    image: ghcr.io/example/app@sha256:" + "a" * 64 + "\n"
            "  sidecar:\n"
            "    image: ghcr.io/example/side@sha256:" + "b" * 64 + "\n"
        )
        links = mv.extract_sigstore_links(compose)
        assert len(links) == 2
        assert links[0].endswith(f"sha256:{'a' * 64}")
        assert links[1].endswith(f"sha256:{'b' * 64}")
        assert all(link.startswith(mv.SIGSTORE_SEARCH_BASE) for link in links)

    def test_deduplicates_preserving_first_occurrence(self):
        digest = "c" * 64
        compose = f"image: one@sha256:{digest}\nimage: two@sha256:{digest}\n"
        links = mv.extract_sigstore_links(compose)
        assert len(links) == 1
        assert links[0].endswith(f"sha256:{digest}")

    def test_empty_compose_returns_empty_list(self):
        assert mv.extract_sigstore_links("") == []
        assert mv.extract_sigstore_links(None) == []


# ---------------------------------------------------------------------------
# _parsed_tcb_info
# ---------------------------------------------------------------------------

class TestParsedTcbInfo:
    def test_handles_dict_tcb_info(self):
        att = {"info": {"tcb_info": {"app_compose": "services: {}"}}}
        assert mv._parsed_tcb_info(att) == {"app_compose": "services: {}"}

    def test_handles_stringified_tcb_info(self):
        att = {"info": {"tcb_info": json.dumps({"app_compose": "hi"})}}
        assert mv._parsed_tcb_info(att) == {"app_compose": "hi"}

    def test_missing_info_returns_none(self):
        assert mv._parsed_tcb_info({}) is None
        assert mv._parsed_tcb_info({"info": {}}) is None


# ---------------------------------------------------------------------------
# base64url_decode_jwt_payload
# ---------------------------------------------------------------------------

class TestBase64UrlDecodeJwtPayload:
    def test_decodes_padded_and_unpadded(self):
        # minimal JWT header.payload.signature form; only the payload is inspected
        import base64
        payload = {"iss": "nvidia", "x-nvidia-overall-att-result": True}
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        jwt = f"h.{encoded}.s"
        decoded = mv.base64url_decode_jwt_payload(jwt)
        assert json.loads(decoded) == payload


# ---------------------------------------------------------------------------
# check_report_data — validated against a real captured bundle
# ---------------------------------------------------------------------------

class TestCheckReportDataAgainstGoldenBundle:
    """Feed ``check_report_data`` the real ``report_data`` bytes from the golden
    bundle via a stubbed ``intel_result`` and verify the boolean verdicts."""

    def _stub_intel_result(self, attestation):
        return {"quote": {"body": {"reportdata": attestation["report_data"], "mrconfig": ""}}}

    def test_happy_path_binds_address_and_nonce(self, golden_gateway, golden_nonce):
        intel_result = self._stub_intel_result(golden_gateway)
        result = mv.check_report_data(golden_gateway, golden_nonce, intel_result)
        assert result == {"binds_address": True, "embeds_nonce": True}

    def test_wrong_nonce_flips_embeds_nonce(self, golden_gateway):
        intel_result = self._stub_intel_result(golden_gateway)
        bad_nonce = "00" * 32
        result = mv.check_report_data(golden_gateway, bad_nonce, intel_result)
        assert result["binds_address"] is True
        assert result["embeds_nonce"] is False

    def test_wrong_signing_address_flips_binds_address(self, golden_gateway, golden_nonce):
        intel_result = self._stub_intel_result(golden_gateway)
        tampered = dict(golden_gateway)
        tampered["signing_address"] = "0x" + "ee" * 20
        result = mv.check_report_data(tampered, golden_nonce, intel_result)
        assert result["binds_address"] is False
        assert result["embeds_nonce"] is True


# ---------------------------------------------------------------------------
# Fixture shape sanity — documents what fields the golden bundle provides
# ---------------------------------------------------------------------------

class TestGoldenFixtureShape:
    def test_top_level_keys(self, golden_report):
        assert set(golden_report.keys()) >= {"gateway_attestation", "model_attestations"}

    def test_gateway_has_required_fields(self, golden_gateway):
        for field in ("signing_address", "signing_algo", "intel_quote", "report_data", "request_nonce", "info"):
            assert field in golden_gateway, f"missing {field}"

    def test_model_has_e2ee_and_gpu_fields(self, golden_model):
        for field in ("signing_public_key", "intel_quote", "nvidia_payload", "info"):
            assert field in golden_model, f"missing {field}"
