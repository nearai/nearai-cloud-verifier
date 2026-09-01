"""Focused regression tests for report-data bindings and evidence selection."""

from __future__ import annotations

import unittest
from hashlib import sha256
from unittest.mock import AsyncMock, patch

from py.common.dstack_attestation import (
    verify_report_data_binding,
    verify_report_data_binding_with_tls_fingerprint,
)
from py.direct.model_tls_attestation import verify_direct_model_tls_attestation
from py.gateway.cloud_api import (
    fetch_model_attestation_for_signature,
    find_model_attestation_for_signature,
)


NONCE = "ab" * 32
SIGNING_ADDRESS = "11" * 20
TLS_FINGERPRINT = "22" * 32


def _quote(report_data: bytes) -> dict:
    return {"quote": {"body": {"reportdata": report_data.hex()}}}


def _model_attestation(**extra: object) -> dict:
    return {
        "signing_algo": "ecdsa",
        "signing_address": SIGNING_ADDRESS,
        **extra,
    }


def _provider_signature() -> dict:
    return {
        "signature_kind": "provider_tee",
        "signing_algo": "ecdsa",
        "signing_address": SIGNING_ADDRESS,
    }


class ReportDataBindingTests(unittest.TestCase):
    def test_no_tls_binding_rejects_a_tls_fingerprint(self) -> None:
        report_data = bytes.fromhex(SIGNING_ADDRESS) + bytes(12) + bytes.fromhex(NONCE)
        result = verify_report_data_binding(
            _model_attestation(tls_cert_fingerprint=TLS_FINGERPRINT),
            NONCE,
            _quote(report_data),
        )

        self.assertFalse(result["binds_signer"])

    def test_no_tls_binding_treats_null_report_data_as_absent(self) -> None:
        report_data = bytes.fromhex(SIGNING_ADDRESS) + bytes(12) + bytes.fromhex(NONCE)
        result = verify_report_data_binding(
            _model_attestation(report_data=None),
            NONCE,
            _quote(report_data),
        )

        self.assertTrue(result["report_data_matches_quote"])
        self.assertTrue(result["binds_signer"])
        self.assertTrue(result["embeds_nonce"])

    def test_tls_binding_requires_a_fingerprint(self) -> None:
        report_data = bytes.fromhex(SIGNING_ADDRESS) + bytes(12) + bytes.fromhex(NONCE)
        result = verify_report_data_binding_with_tls_fingerprint(
            _model_attestation(),
            NONCE,
            _quote(report_data),
        )

        self.assertFalse(result["binds_signer"])

    def test_gateway_tls_binding_requires_report_data(self) -> None:
        report_data = sha256(
            bytes.fromhex(SIGNING_ADDRESS) + bytes.fromhex(TLS_FINGERPRINT)
        ).digest() + bytes.fromhex(NONCE)
        result = verify_report_data_binding_with_tls_fingerprint(
            _model_attestation(
                report_data=None,
                tls_cert_fingerprint=TLS_FINGERPRINT,
            ),
            NONCE,
            _quote(report_data),
            require_advertised_report_data=True,
        )

        self.assertFalse(result["report_data_matches_quote"])
        self.assertTrue(result["binds_signer"])


class ModelEvidenceSelectionTests(unittest.TestCase):
    def test_fetch_for_signature_delegates_to_fetch_then_find(self) -> None:
        candidate = _model_attestation()
        with patch(
            "py.gateway.cloud_api.fetch_model_attestations",
            return_value=([candidate], NONCE),
        ) as fetch:
            selected, nonce = fetch_model_attestation_for_signature(
                "canonical-model", _provider_signature()
            )

        self.assertIs(selected, candidate)
        self.assertEqual(nonce, NONCE)
        fetch.assert_called_once_with(
            "canonical-model",
            signing_algo="ecdsa",
            signing_address=SIGNING_ADDRESS,
        )
        self.assertIs(
            find_model_attestation_for_signature([candidate], _provider_signature()),
            candidate,
        )


class DirectModelTlsTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_an_advertised_report_data_mismatch(self) -> None:
        quote_report_data = sha256(
            bytes.fromhex(SIGNING_ADDRESS) + bytes.fromhex(TLS_FINGERPRINT)
        ).digest() + bytes.fromhex(NONCE)
        attestation = {
            "request_nonce": NONCE,
            "signing_address": SIGNING_ADDRESS,
            "signing_algo": "ecdsa",
            "tls_cert_fingerprint": TLS_FINGERPRINT,
            "report_data": "00" * 64,
        }
        verified_quote = _quote(quote_report_data)
        verified_quote.update({"verified": True, "debug_enabled": False})
        with (
            patch(
                "py.direct.model_tls_attestation.secrets.token_hex",
                return_value=NONCE,
            ),
            patch(
                "py.direct.model_tls_attestation.fetch_model_attestation_and_spki",
                return_value=(attestation, TLS_FINGERPRINT),
            ),
            patch(
                "py.direct.model_tls_attestation.verify_dstack_quote",
                new=AsyncMock(return_value=verified_quote),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "does not match report_data"):
                await verify_direct_model_tls_attestation("https://model.example")

    async def test_rejects_an_attestation_nonce_mismatch(self) -> None:
        with (
            patch(
                "py.direct.model_tls_attestation.secrets.token_hex",
                return_value=NONCE,
            ),
            patch(
                "py.direct.model_tls_attestation.fetch_model_attestation_and_spki",
                return_value=({"request_nonce": "00" * 32}, TLS_FINGERPRINT),
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "request_nonce does not match"):
                await verify_direct_model_tls_attestation("https://model.example")


if __name__ == "__main__":
    unittest.main()
