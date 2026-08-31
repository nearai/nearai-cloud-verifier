#!/usr/bin/env python3
"""Independent reference verifier for signed NEAR AI Cloud responses.

The signature endpoint supplies ``signature_kind``. That field selects the
trust boundary and is never inferred from the colon-separated signed text:

* ``provider_tee`` signs model request/response hashes and is bound to model
  evidence;
* ``gateway`` signs the client-visible request/response hashes and is bound to
  Gateway evidence and the TLS peer observed while fetching that evidence.

The examples retain the exact request and response bytes. JSON and SSE parsing
is used only to discover the completion id after those bytes have been saved.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from hashlib import sha256
from typing import Any, Dict, List, Optional, Sequence, Union
from urllib.parse import quote

import nacl.exceptions
import nacl.signing
import requests
from eth_account import Account
from eth_account.messages import encode_defunct

from model_verifier import (
    API_KEY,
    BASE_URL,
    AttestationVerificationError,
    VerificationFailure,
    decode_hex,
    fetch_gateway_attestation_for_signature,
    fetch_model_attestation_for_signature,
    signing_identity,
    verify_attestation,
)


SUPPORTED_SIGNATURE_KINDS = {"provider_tee", "gateway"}


class ResponseVerificationError(RuntimeError):
    """Raised after response-signature and evidence failures have been printed."""

    def __init__(self, failures: Sequence[VerificationFailure]):
        self.failures = tuple(failures)
        summary = "; ".join(f"{failure.check}: {failure.detail}" for failure in failures)
        super().__init__(f"Response verification failed ({summary})")


def _cloud_api_url(path: str) -> str:
    base = BASE_URL.rstrip("/")
    if base.endswith("/v1"):
        return f"{base}/{path.lstrip('/')}"
    return f"{base}/v1/{path.lstrip('/')}"


def _headers(content_type: bool = False) -> Dict[str, str]:
    headers = {"Authorization": f"Bearer {API_KEY}"} if API_KEY else {}
    if content_type:
        headers["Content-Type"] = "application/json"
    return headers


def _as_bytes(value: Union[bytes, str], label: str) -> bytes:
    """Accept legacy text callers while making byte use explicit in this file."""

    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{label} must be bytes (or legacy UTF-8 text)")


def sha256_bytes(value: bytes) -> str:
    """Calculate a SHA-256 digest over the exact bytes supplied by the client."""

    return sha256(value).hexdigest()


def fetch_signature(
    completion_id: str,
    signing_algo: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch one completion signature.

    The signature lookup is keyed by completion id and signing algorithm. The
    model is read from the original request bytes only when provider evidence
    is needed.
    """

    params = {} if signing_algo is None else {"signing_algo": signing_algo}
    response = requests.get(
        _cloud_api_url(f"signature/{quote(completion_id, safe='')}"),
        params=params,
        headers=_headers(),
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("signature endpoint returned a non-object JSON value")
    if isinstance(payload.get("error_code"), str):
        raise ValueError(
            "signature is unavailable: "
            f"{payload.get('error_code')}: {payload.get('message', '')}"
        )
    return payload


def _require_signature_kind(signature: Dict[str, Any]) -> str:
    kind = signature.get("signature_kind")
    if kind not in SUPPORTED_SIGNATURE_KINDS:
        raise ValueError(
            "signature_kind is required and must be 'provider_tee' or 'gateway'; "
            f"received {kind!r}"
        )
    return kind


def _model_from_request(request_body: bytes) -> str:
    try:
        value = json.loads(request_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("provider_tee verification requires a JSON request body") from error
    if not isinstance(value, dict) or not isinstance(value.get("model"), str):
        raise ValueError("provider_tee verification requires request JSON with a model string")
    if not value["model"]:
        raise ValueError("provider_tee verification requires a non-empty request model")
    return value["model"]


def _expected_signed_text(kind: str, request_body: bytes, response_body: bytes) -> str:
    request_hash = sha256_bytes(request_body)
    response_hash = sha256_bytes(response_body)
    if kind == "provider_tee":
        return f"{_model_from_request(request_body)}:{request_hash}:{response_hash}"
    return f"{request_hash}:{response_hash}"


def recover_signer(text: str, signature: str) -> str:
    """Recover the Ethereum address from a legacy/ECDSA response signature."""

    return Account.recover_message(encode_defunct(text=text), signature=signature)


def _verify_ecdsa_signature(signature: Dict[str, Any], signed_text: str) -> bool:
    try:
        _, expected_address = signing_identity(signature, "signature")
        signature_bytes = decode_hex(signature.get("signature"), "signature.signature")
        if len(signature_bytes) != 65:
            raise ValueError("ECDSA signature must be 65 bytes")
        recovered = recover_signer(signed_text, signature["signature"])
        recovered_bytes = decode_hex(recovered, "recovered signing address")
        return recovered_bytes == expected_address
    except (ValueError, TypeError, AttributeError) as error:
        print("ECDSA signature verification failed:", error)
        return False


def _verify_ed25519_signature(signature: Dict[str, Any], signed_text: str) -> bool:
    try:
        _, public_key = signing_identity(signature, "signature")
        signed = decode_hex(signature.get("signature"), "signature.signature")
        if len(signed) != 64:
            raise ValueError("Ed25519 signature must be 64 bytes")
        nacl.signing.VerifyKey(public_key).verify(signed_text.encode("utf-8"), signed)
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError) as error:
        print("Ed25519 signature verification failed:", error)
        return False


def verify_response_signature(
    signature: Dict[str, Any], request_body: bytes, response_body: bytes
) -> List[VerificationFailure]:
    """Check signed text, exact byte hashes, and the response signature itself."""

    failures: List[VerificationFailure] = []
    kind = _require_signature_kind(signature)
    signed_text = signature.get("text")
    if not isinstance(signed_text, str):
        raise ValueError("signature.text must be a string")

    try:
        expected = _expected_signed_text(kind, request_body, response_body)
        text_matches = signed_text == expected
    except ValueError as error:
        expected = None
        text_matches = False
        print("Signature text matches exact request/response bytes:", False)
        print("  error:", error)
    else:
        print("Signature kind:", kind)
        print("Request SHA-256:", sha256_bytes(request_body))
        print("Response SHA-256:", sha256_bytes(response_body))
        print("Signature text matches exact request/response bytes:", text_matches)
        if not text_matches:
            print("  expected:", expected)
            print("  actual:  ", signed_text)
    if not text_matches:
        failures.append(
            VerificationFailure(
                "response hash binding",
                "signature text does not match the exact request/response bytes",
            )
        )

    signing_algo = signature.get("signing_algo")
    if signing_algo == "ecdsa":
        cryptographically_valid = _verify_ecdsa_signature(signature, signed_text)
    elif signing_algo == "ed25519":
        cryptographically_valid = _verify_ed25519_signature(signature, signed_text)
    else:
        cryptographically_valid = False
        print("Response signature uses a supported signing algorithm:", False)
    print("Response signature is cryptographically valid:", cryptographically_valid)
    if not cryptographically_valid:
        failures.append(
            VerificationFailure(
                "response signature",
                "signature did not verify against its advertised signer",
            )
        )
    return failures


def _append_attestation_failures(
    failures: List[VerificationFailure], error: AttestationVerificationError
) -> None:
    for failure in error.failures:
        failures.append(VerificationFailure(f"attestation: {failure.check}", failure.detail))


async def verify_chat(
    chat_id: str,
    request_body: Union[bytes, str],
    response_body: Union[bytes, str],
    label: str,
    signing_algo: Optional[str] = None,
) -> None:
    """Verify one signed Cloud API completion against its declared trust boundary.

    The provider-evidence lookup derives the canonical model from
    ``request_body``. Gateway-signed responses always verify the TLS peer that
    served their Gateway evidence; provider-TEE responses use model evidence
    and have no Gateway TLS assertion to make.
    """

    request_bytes = _as_bytes(request_body, "request_body")
    response_bytes = _as_bytes(response_body, "response_body")
    failures: List[VerificationFailure] = []

    print(f"\n--- {label} ---")
    signature = fetch_signature(chat_id, signing_algo=signing_algo)
    print(json.dumps(signature, indent=2))
    kind = _require_signature_kind(signature)
    failures.extend(verify_response_signature(signature, request_bytes, response_bytes))

    try:
        if kind == "provider_tee":
            print("\n🔐 Model attestation for provider_tee signature")
            attestation, nonce = fetch_model_attestation_for_signature(
                _model_from_request(request_bytes), signature
            )
            await verify_attestation(
                attestation,
                nonce,
                verify_model=True,
                expected_signer=signature,
            )
        else:
            print("\n🔐 Gateway attestation for gateway signature")
            attestation, nonce, peer_spki = fetch_gateway_attestation_for_signature(
                signature
            )
            await verify_attestation(
                attestation,
                nonce,
                require_peer_tls_binding=True,
                peer_spki_fingerprint=peer_spki,
                expected_signer=signature,
            )
    except AttestationVerificationError as error:
        _append_attestation_failures(failures, error)
    except (requests.RequestException, RuntimeError, ValueError) as error:
        failures.append(VerificationFailure("attestation fetch", str(error)))

    if failures:
        print("\n✗ Response verification summary")
        for failure in failures:
            print(f"  - {failure.check}: {failure.detail}")
        raise ResponseVerificationError(failures)
    print("\n✓ Response verification passed")


def _completion_id_from_stream(response_body: bytes) -> str:
    """Parse an SSE completion id without reconstructing the signed bytes."""

    for line in response_body.splitlines():
        if not line.startswith(b"data:"):
            continue
        payload = line[5:].strip()
        if payload == b"[DONE]":
            continue
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("id"), str):
            return value["id"]
    raise ValueError("streaming response did not contain a completion id")


def _completion_id_from_json(response_body: bytes) -> str:
    try:
        value = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("non-streaming response is not JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("id"), str):
        raise ValueError("non-streaming response did not contain a completion id")
    return value["id"]


def _post_completion(request_body: bytes, streaming: bool) -> bytes:
    """Return exactly the bytes emitted by the Cloud API response body."""

    response = requests.post(
        _cloud_api_url("chat/completions"),
        headers={
            **_headers(content_type=True),
            "Accept-Encoding": "identity",
            "x-no-aliasing": "true",
        },
        data=request_body,
        stream=streaming,
        timeout=30,
    )
    response.raise_for_status()
    if not streaming:
        return response.content
    return b"".join(response.iter_content(chunk_size=None))


async def streaming_example(model: str, signing_algo: Optional[str] = None) -> None:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": True,
        "max_tokens": 1,
    }
    request_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    response_body = _post_completion(request_body, streaming=True)
    chat_id = _completion_id_from_stream(response_body)
    await verify_chat(
        chat_id,
        request_body,
        response_body,
        "Streaming example",
        signing_algo=signing_algo,
    )


async def non_streaming_example(model: str, signing_algo: Optional[str] = None) -> None:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "Hello, how are you?"}],
        "stream": False,
        "max_tokens": 1,
    }
    request_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    response_body = _post_completion(request_body, streaming=False)
    chat_id = _completion_id_from_json(response_body)
    await verify_chat(
        chat_id,
        request_body,
        response_body,
        "Non-streaming example",
        signing_algo=signing_algo,
    )


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify signed NEAR AI Cloud chat responses"
    )
    parser.add_argument("--model", default="deepseek-ai/DeepSeek-V3.1")
    parser.add_argument(
        "--signing-algo",
        choices=["ecdsa", "ed25519"],
        help="Lookup a specific signature algorithm; omit for the Cloud API default.",
    )
    args = parser.parse_args()

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        return 2

    failures: List[VerificationFailure] = []
    for example in (streaming_example, non_streaming_example):
        try:
            await example(args.model, args.signing_algo)
        except (ResponseVerificationError, requests.RequestException, ValueError) as error:
            print(f"{example.__name__} failed:", error)
            failures.append(VerificationFailure(example.__name__, str(error)))
    if failures:
        print("\n✗ One or more chat verification examples failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
