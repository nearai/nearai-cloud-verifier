"""Cloud API evidence retrieval and response decoding.

These helpers fetch or select evidence only. Callers must verify the returned
evidence separately before treating it as trusted.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
from hashlib import sha256
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlencode, urlsplit

import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from py.utils.attestation import (
    decode_hex,
    signing_identities_match,
)


BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")
API_KEY = os.environ.get("API_KEY", "")


def cloud_api_url(path: str) -> str:
    """Return one Cloud API URL while accepting a base URL ending in ``/v1``."""

    base = BASE_URL.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/{path.lstrip('/')}"
    return f"{base}/v1/{path.lstrip('/')}"


def cloud_api_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return request headers with the configured API key when present."""

    headers = {} if extra is None else dict(extra)
    if API_KEY:
        headers["Authorization"] = f"Bearer {API_KEY}"
    return headers


def _request_json(
    path: str,
    params: Dict[str, str],
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    response = requests.get(
        cloud_api_url(path),
        params=params,
        headers=cloud_api_headers(headers),
        timeout=30,
    )
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError(f"{path} returned {type(value).__name__}, expected a JSON object")
    return value


def fetch_model_attestations(
    model: str,
    nonce: str,
    signing_algo: Optional[str] = None,
    signing_address: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch NEAR model evidence for a caller-provided nonce and no TLS binding."""

    nonce_bytes = decode_hex(nonce, "nonce")
    if len(nonce_bytes) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(nonce_bytes)}")
    params = {
        "model": model,
        "provider": "near",
        "nonce": nonce,
        "include_tls_fingerprint": "false",
    }
    if signing_algo is not None:
        params["signing_algo"] = signing_algo
    if signing_address is not None:
        params["signing_address"] = signing_address
    report = _request_json(
        "attestation/report",
        params,
        headers={"x-no-aliasing": "true"},
    )
    attestations = report.get("model_attestations")
    if not isinstance(attestations, list) or not attestations or not all(
        isinstance(attestation, dict) for attestation in attestations
    ):
        raise ValueError("Cloud API model report does not contain model_attestations[]")
    for attestation in attestations:
        reported_nonce = decode_hex(
            attestation.get("request_nonce"), "attestation.request_nonce"
        )
        if len(reported_nonce) != 32:
            raise ValueError(
                "Cloud API attestation request_nonce must be 32 bytes, "
                f"got {len(reported_nonce)}"
            )
        if reported_nonce != nonce_bytes:
            raise ValueError(
                "Cloud API attestation request_nonce does not match the requested nonce"
            )
    return attestations


def find_model_attestation_for_signature(
    attestations: Sequence[Dict[str, Any]],
    signature: Mapping[str, Any],
) -> Dict[str, Any]:
    """Select the one model attestation matching a signature signer.

    This is signer selection only. It neither interprets ``signature_kind``
    nor verifies the selected evidence.
    """

    matches: List[Dict[str, Any]] = []
    for attestation in attestations:
        try:
            if signing_identities_match(attestation, signature):
                matches.append(attestation)
        except (TypeError, ValueError):
            continue
    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one NEAR model attestation for the signature signer; "
            f"found {len(matches)}"
        )
    return matches[0]


def _peer_spki_fingerprint(certificate_der: bytes) -> str:
    certificate = x509.load_der_x509_certificate(certificate_der)
    spki_der = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(spki_der).hexdigest()


def _fetch_gateway_report_with_peer_spki(
    params: Dict[str, str]
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch Gateway evidence and retain the TLS peer from that same request."""

    url = urlsplit(cloud_api_url("attestation/report"))
    if url.scheme != "https" or not url.hostname:
        # Local HTTP is useful for development but has no peer certificate.
        return _request_json("attestation/report", params), None

    path = url.path or "/"
    query = urlencode(params)
    if url.query:
        query = f"{url.query}&{query}"
    if query:
        path = f"{path}?{query}"

    connection = http.client.HTTPSConnection(
        url.hostname,
        url.port or 443,
        context=ssl.create_default_context(),
        timeout=30,
    )
    try:
        connection.connect()
        socket = connection.sock
        if socket is None:
            raise RuntimeError("HTTPS connection did not expose a TLS socket")
        certificate_der = socket.getpeercert(binary_form=True)
        if not certificate_der:
            raise RuntimeError("TLS peer did not provide a certificate")
        peer_spki = _peer_spki_fingerprint(certificate_der)

        connection.request("GET", path, headers=cloud_api_headers())
        response = connection.getresponse()
        body = response.read()
        if not 200 <= response.status < 300:
            rendered = body.decode("utf-8", "replace")
            raise RuntimeError(f"Cloud API returned HTTP {response.status}: {rendered}")
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError("attestation/report returned a non-object JSON value")
        return value, peer_spki
    finally:
        connection.close()


def fetch_gateway_attestation(
    nonce: str,
    signing_algo: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """Fetch Gateway evidence for a caller-provided nonce and its TLS peer."""

    nonce_bytes = decode_hex(nonce, "nonce")
    if len(nonce_bytes) != 32:
        raise ValueError(f"nonce must be 32 bytes, got {len(nonce_bytes)}")
    params = {"nonce": nonce, "include_tls_fingerprint": "true"}
    if signing_algo is not None:
        params["signing_algo"] = signing_algo
    report, peer_spki = _fetch_gateway_report_with_peer_spki(params)
    attestation = report.get("gateway_attestation")
    if not isinstance(attestation, dict):
        raise ValueError("Cloud API Gateway report does not contain gateway_attestation")
    reported_nonce = decode_hex(
        attestation.get("request_nonce"), "attestation.request_nonce"
    )
    if len(reported_nonce) != 32:
        raise ValueError(
            "Cloud API attestation request_nonce must be 32 bytes, "
            f"got {len(reported_nonce)}"
        )
    if reported_nonce != nonce_bytes:
        raise ValueError(
            "Cloud API attestation request_nonce does not match the requested nonce"
        )
    return attestation, peer_spki
