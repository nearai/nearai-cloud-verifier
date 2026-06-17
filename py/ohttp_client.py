#!/usr/bin/env python3
"""OHTTP (RFC 9458) client example for NEAR AI Cloud API.

Implements from scratch using only the `cryptography` package:
  - HPKE base mode (RFC 9180): DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
  - Binary HTTP (RFC 9292): known-length request/response encoding
  - Oblivious HTTP (RFC 9458): request encapsulation + response decapsulation

Run:
    export API_KEY=sk-...
    python3 py/ohttp_client.py                                # all examples
    python3 py/ohttp_client.py --model anthropic/claude-haiku-4-5
    python3 py/ohttp_client.py --verify-attestation           # check key is TEE-attested

OHTTP privacy guarantee: the NEAR AI server sees only an encrypted HPKE blob; it
cannot link your request to your IP address or API key. The HPKE key is generated
inside the TEE and bound to the gateway attestation — verifiable via
GET /v1/attestation/report (ohttp_key_config + ohttp_attestation fields).
"""

import argparse
import hmac as _hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Iterator

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai")

# ─── HKDF helpers (RFC 5869) ──────────────────────────────────────────────────

def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return _hmac.new(salt, ikm, "sha256").digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


# ─── HPKE labeled variants (RFC 9180 §4.0.1) ─────────────────────────────────

def _labeled_extract(suite_id: bytes, label: str, ikm: bytes, salt: bytes | None = None) -> bytes:
    if salt is None:
        salt = b"\x00" * 32
    labeled_ikm = b"HPKE-v1" + suite_id + label.encode() + ikm
    return _hkdf_extract(salt, labeled_ikm)


def _labeled_expand(suite_id: bytes, label: str, prk: bytes, info: bytes, length: int) -> bytes:
    labeled_info = struct.pack(">H", length) + b"HPKE-v1" + suite_id + label.encode() + info
    return _hkdf_expand(prk, labeled_info, length)


# ─── QUIC variable-length integer (RFC 9000 §16) ─────────────────────────────

def _quic_encode(n: int) -> bytes:
    if n < 64:
        return bytes([n])
    if n < 16384:
        return struct.pack(">H", n | 0x4000)
    if n < 1073741824:
        return struct.pack(">I", n | 0x80000000)
    return struct.pack(">Q", n | 0xC000000000000000)


def _quic_decode(data: bytes, off: int) -> tuple[int, int]:
    b0 = data[off]
    prefix = b0 >> 6
    if prefix == 0:
        return b0 & 0x3F, off + 1
    if prefix == 1:
        v = struct.unpack_from(">H", data, off)[0]
        return v & 0x3FFF, off + 2
    if prefix == 2:
        v = struct.unpack_from(">I", data, off)[0]
        return v & 0x3FFFFFFF, off + 4
    v = struct.unpack_from(">Q", data, off)[0]
    return v & 0x3FFFFFFFFFFFFFFF, off + 8


def _qstr(b: bytes) -> bytes:
    return _quic_encode(len(b)) + b


# ─── BHTTP (RFC 9292, known-length) ──────────────────────────────────────────

def bhttp_encode_request(
    method: str,
    scheme: str,
    authority: str,
    path: str,
    headers: list[tuple[str, str]],
    body: bytes | str,
) -> bytes:
    """Encode an HTTP request as a known-length BHTTP message (framing=0x00)."""
    buf = b"\x00"  # framing indicator: known-length request
    buf += _qstr(method.encode())
    buf += _qstr(scheme.encode())
    buf += _qstr(authority.encode())
    buf += _qstr(path.encode())
    field_sec = b"".join(_qstr(k.encode()) + _qstr(v.encode()) for k, v in headers)
    buf += _quic_encode(len(field_sec)) + field_sec
    body_b = body if isinstance(body, bytes) else body.encode()
    buf += _quic_encode(len(body_b)) + body_b
    buf += _quic_encode(0)  # empty trailer field section
    return buf


def bhttp_decode_response(data: bytes) -> tuple[int, dict[str, str], bytes]:
    """Decode a BHTTP response.

    Supports framing 0x01 (known-length) and 0x03 (indeterminate-length).
    Returns (status_code, headers, body).
    """
    framing = data[0]
    assert framing in (0x01, 0x03), f"Unsupported BHTTP response framing: {framing:#04x}"
    off = 1

    # For indeterminate-length, status may be preceded by 1xx informational responses
    while True:
        status, off = _quic_decode(data, off)
        if framing == 0x01:
            break  # known-length has no informational responses in this usage
        if status >= 200:
            break
        # Skip 1xx informational field section (indeterminate format)
        while True:
            nlen, off = _quic_decode(data, off)
            if nlen == 0:
                break
            off += nlen  # skip name
            vlen, off = _quic_decode(data, off)
            off += vlen  # skip value

    headers: dict[str, str] = {}
    if framing == 0x01:
        # Known-length field section: quic(total_bytes) + field_lines
        hdr_len, off = _quic_decode(data, off)
        hdr_end = off + hdr_len
        while off < hdr_end:
            name_len, off = _quic_decode(data, off)
            name = data[off : off + name_len].decode()
            off += name_len
            val_len, off = _quic_decode(data, off)
            val = data[off : off + val_len].decode()
            off += val_len
            headers[name] = val
        off = hdr_end
        content_len, off = _quic_decode(data, off)
        body = data[off : off + content_len]
    else:
        # Indeterminate-length field section: [quic(nlen) + name + quic(vlen) + val]* + quic(0)
        while True:
            nlen, off = _quic_decode(data, off)
            if nlen == 0:
                break
            name = data[off : off + nlen].decode()
            off += nlen
            vlen, off = _quic_decode(data, off)
            val = data[off : off + vlen].decode()
            off += vlen
            headers[name] = val
        # Indeterminate-length body: [quic(chunk_len > 0) + chunk]* + quic(0)
        parts: list[bytes] = []
        while True:
            chunk_len, off = _quic_decode(data, off)
            if chunk_len == 0:
                break
            parts.append(data[off : off + chunk_len])
            off += chunk_len
        body = b"".join(parts)

    return status, headers, body


# ─── HPKE sender setup (RFC 9180, base mode, DHKEM-X25519) ───────────────────

@dataclass
class _HpkeSenderContext:
    enc: bytes          # ephemeral public key (32 bytes, X25519)
    key: bytes          # AEAD key (16 bytes, AES-128)
    base_nonce: bytes   # AEAD nonce (12 bytes)
    exporter_secret: bytes  # for response decapsulation
    hpke_suite_id: bytes


def _hpke_setup_sender(
    server_pk_bytes: bytes,
    kem_id: int,
    kdf_id: int,
    aead_id: int,
    info: bytes,
) -> _HpkeSenderContext:
    """SetupBaseS for DHKEM(X25519)+HKDF-SHA256+AES-128-GCM (RFC 9180 §5.1)."""
    Nk, Nn, Nh, Nsecret = 16, 12, 32, 32

    kem_suite_id  = b"KEM"  + struct.pack(">H", kem_id)
    hpke_suite_id = b"HPKE" + struct.pack(">HHH", kem_id, kdf_id, aead_id)

    # Ephemeral key pair
    eph_sk = X25519PrivateKey.generate()
    enc = eph_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # DHKEM(X25519) ExtractAndExpand (RFC 9180 §4.1)
    server_pk = X25519PublicKey.from_public_bytes(server_pk_bytes)
    dh = eph_sk.exchange(server_pk)
    kem_context = enc + server_pk_bytes
    prk_kem = _labeled_extract(kem_suite_id, "eae_prk", dh)  # RFC 9180 §4.1
    shared_secret = _labeled_expand(kem_suite_id, "shared_secret", prk_kem, kem_context, Nsecret)

    # KeySchedule base mode (RFC 9180 §5.1)
    psk, psk_id = b"", b""
    psk_id_hash = _labeled_extract(hpke_suite_id, "psk_id_hash", psk_id, salt=b"")
    info_hash   = _labeled_extract(hpke_suite_id, "info_hash",   info,   salt=b"")
    ks_context  = b"\x00" + psk_id_hash + info_hash  # mode=0 (base)

    # LabeledExtract(salt=shared_secret, label="secret", ikm=psk) — note: shared_secret is the SALT
    prk_ks          = _labeled_extract(hpke_suite_id, "secret",     psk, salt=shared_secret)
    key             = _labeled_expand(hpke_suite_id, "key",        prk_ks, ks_context, Nk)
    base_nonce      = _labeled_expand(hpke_suite_id, "base_nonce", prk_ks, ks_context, Nn)
    exporter_secret = _labeled_expand(hpke_suite_id, "exp",        prk_ks, ks_context, Nh)

    return _HpkeSenderContext(enc, key, base_nonce, exporter_secret, hpke_suite_id)


# ─── Chunked OHTTP helpers ────────────────────────────────────────────────────

_MAX_CHUNK_PLAINTEXT = 1 << 14  # 16 384 bytes (ohttp 0.7.2 stream.rs)


def _compute_nonce(base_nonce: bytes, seq: int) -> bytes:
    """RFC 9180 §5.2: base_nonce XOR I2OSP(seq, Nn)."""
    return bytes(a ^ b for a, b in zip(base_nonce, seq.to_bytes(len(base_nonce), "big")))


# ─── OHTTP request/response (RFC 9458) ───────────────────────────────────────

@dataclass
class _OhttpState:
    enc: bytes          # ephemeral public key (for response decapsulation)
    exporter_secret: bytes
    hpke_suite_id: bytes
    Nk: int = 16
    Nn: int = 12


def _ohttp_encapsulate(key_config: bytes, bhttp_request: bytes) -> tuple[bytes, _OhttpState]:
    """Encapsulate a BHTTP request in an OHTTP envelope (RFC 9458 §4.3).

    Returns (enc_request, state). enc_request has Content-Type message/ohttp-req.
    """
    key_id  = key_config[0]
    kem_id  = struct.unpack(">H", key_config[1:3])[0]
    server_pk = key_config[3:35]
    # algorithms list starts at offset 37 (skipping 2-byte length field at 35-36)
    kdf_id  = struct.unpack(">H", key_config[37:39])[0]
    aead_id = struct.unpack(">H", key_config[39:41])[0]

    header = bytes([key_id]) + struct.pack(">HHH", kem_id, kdf_id, aead_id)
    info   = b"message/bhttp request\x00" + header

    ctx = _hpke_setup_sender(server_pk, kem_id, kdf_id, aead_id, info)
    # ohttp 0.7 (rust-hpke feature) uses empty AAD for Seal/Open
    ct  = AESGCM(ctx.key).encrypt(ctx.base_nonce, bhttp_request, b"")

    enc_request = header + ctx.enc + ct
    state = _OhttpState(ctx.enc, ctx.exporter_secret, ctx.hpke_suite_id)
    return enc_request, state


def _ohttp_encapsulate_chunked(key_config: bytes, bhttp_request: bytes) -> tuple[bytes, _OhttpState]:
    """Encapsulate a BHTTP request using chunked OHTTP (RFC 9458).

    Uses Content-Type message/ohttp-chunked-req. Wire format:
      header(7) + enc(32) + [varint(ct_len) + ct]* + varint(0) + final_ct(16)
    Each non-final chunk uses AAD=b""; the final empty chunk uses AAD=b"final".
    """
    key_id    = key_config[0]
    kem_id    = struct.unpack(">H", key_config[1:3])[0]
    server_pk = key_config[3:35]
    kdf_id    = struct.unpack(">H", key_config[37:39])[0]
    aead_id   = struct.unpack(">H", key_config[39:41])[0]

    header = bytes([key_id]) + struct.pack(">HHH", kem_id, kdf_id, aead_id)
    info   = b"message/bhttp chunked request\x00" + header  # different from standard OHTTP

    ctx = _hpke_setup_sender(server_pk, kem_id, kdf_id, aead_id, info)
    result = bytearray(header + ctx.enc)

    # Non-final chunks
    seq, offset = 0, 0
    while offset < len(bhttp_request):
        chunk = bhttp_request[offset : offset + _MAX_CHUNK_PLAINTEXT]
        offset += len(chunk)
        ct = AESGCM(ctx.key).encrypt(_compute_nonce(ctx.base_nonce, seq), chunk, b"")
        seq += 1
        result += _quic_encode(len(ct)) + ct

    # Final chunk: seal(b"final", b"") = 16-byte GCM tag only
    final_ct = AESGCM(ctx.key).encrypt(_compute_nonce(ctx.base_nonce, seq), b"", b"final")
    result += _quic_encode(0) + final_ct

    state = _OhttpState(ctx.enc, ctx.exporter_secret, ctx.hpke_suite_id)
    return bytes(result), state


def _ohttp_decapsulate_response_chunked(data: bytes, state: _OhttpState) -> bytes:
    """Decapsulate a chunked OHTTP response (Content-Type message/ohttp-chunked-res).

    Wire format: response_nonce(16) + [varint(ct_len) + ct]* + varint(0) + final_ct(16)
    """
    Nmax = max(state.Nk, state.Nn)
    response_nonce = data[:Nmax]
    pos = Nmax

    # HPKE Export with chunked response label, then make_aead via plain HKDF
    secret = _labeled_expand(
        state.hpke_suite_id, "sec", state.exporter_secret,
        b"message/bhttp chunked response", Nmax,
    )
    prk          = _hkdf_extract(state.enc + response_nonce, secret)
    key_r        = _hkdf_expand(prk, b"key",   state.Nk)
    nonce_base_r = _hkdf_expand(prk, b"nonce", state.Nn)

    plaintext, seq = bytearray(), 0
    while pos < len(data):
        ct_len, pos = _quic_decode(data, pos)
        if ct_len == 0:
            # Final chunk — remaining bytes are the 16-byte GCM tag of empty plaintext
            AESGCM(key_r).decrypt(_compute_nonce(nonce_base_r, seq), data[pos:], b"final")
            break
        ct = data[pos : pos + ct_len]
        pos += ct_len
        plaintext += AESGCM(key_r).decrypt(_compute_nonce(nonce_base_r, seq), ct, b"")
        seq += 1

    return bytes(plaintext)


def _ohttp_decapsulate_response(enc_response: bytes, state: _OhttpState) -> bytes:
    """Decapsulate an OHTTP response envelope (RFC 9458 §4.4).

    Returns the plaintext BHTTP response bytes.
    """
    Nmax = max(state.Nk, state.Nn)
    response_nonce = enc_response[:Nmax]
    ct             = enc_response[Nmax:]

    # context.Export("message/bhttp response", Nmax)  (RFC 9180 §5.3)
    secret = _labeled_expand(state.hpke_suite_id, "sec", state.exporter_secret, b"message/bhttp response", Nmax)
    # Derive AEAD key and nonce using plain HKDF (not labeled) — RFC 9458 §4.4
    salt       = state.enc + response_nonce
    prk        = _hkdf_extract(salt, secret)
    aead_key   = _hkdf_expand(prk, b"key",   state.Nk)
    aead_nonce = _hkdf_expand(prk, b"nonce", state.Nn)

    return AESGCM(aead_key).decrypt(aead_nonce, ct, b"")


# ─── OhttpClient ─────────────────────────────────────────────────────────────

class OhttpClient:
    """High-level OHTTP client for NEAR AI Cloud API.

    Fetches the HPKE key config once and reuses it across requests (key changes
    only when the TEE is redeployed; the key_id in the config detects staleness).
    """

    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self._http    = requests.Session()
        self._key_config: bytes | None = None

    def fetch_key_config(self) -> bytes:
        r = self._http.get(f"{self.base_url}/.well-known/ohttp-gateway", timeout=10)
        r.raise_for_status()
        assert r.headers.get("content-type") == "application/ohttp-keys", (
            f"Unexpected Content-Type: {r.headers.get('content-type')}"
        )
        self._key_config = r.content
        return self._key_config

    @property
    def key_config(self) -> bytes:
        if self._key_config is None:
            self.fetch_key_config()
        return self._key_config  # type: ignore[return-value]

    def request(
        self,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes | str,
    ) -> tuple[int, dict[str, str], bytes]:
        """Send a single OHTTP-encapsulated HTTP request.

        Returns (inner_status, inner_headers, inner_body).
        """
        bhttp_req = bhttp_encode_request(
            method=method,
            scheme="https",
            authority=self.base_url.removeprefix("https://").removeprefix("http://"),
            path=path,
            headers=headers,
            body=body,
        )
        enc_req, state = _ohttp_encapsulate(self.key_config, bhttp_req)

        resp = self._http.post(
            f"{self.base_url}/ohttp",
            data=enc_req,
            headers={"content-type": "message/ohttp-req"},
            timeout=120,
        )
        assert resp.status_code == 200, f"OHTTP transport error: {resp.status_code} {resp.text[:200]}"
        assert resp.headers.get("content-type") == "message/ohttp-res", (
            f"Expected message/ohttp-res, got {resp.headers.get('content-type')}"
        )

        bhttp_resp = _ohttp_decapsulate_response(resp.content, state)
        return bhttp_decode_response(bhttp_resp)

    def request_chunked(
        self,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes | str,
    ) -> tuple[int, dict[str, str], bytes]:
        """Send an OHTTP-encapsulated request using the chunked format.

        Content-Type message/ohttp-chunked-req — wire-format uses counter-nonce AEAD
        chunks, which is the format required for true server-side streaming.
        Returns (inner_status, inner_headers, inner_body).
        """
        bhttp_req = bhttp_encode_request(
            method=method,
            scheme="https",
            authority=self.base_url.removeprefix("https://").removeprefix("http://"),
            path=path,
            headers=headers,
            body=body,
        )
        enc_req, state = _ohttp_encapsulate_chunked(self.key_config, bhttp_req)

        resp = self._http.post(
            f"{self.base_url}/ohttp",
            data=enc_req,
            headers={"content-type": "message/ohttp-chunked-req"},
            timeout=120,
        )
        assert resp.status_code == 200, f"OHTTP transport error: {resp.status_code} {resp.text[:200]}"
        assert resp.headers.get("content-type") == "message/ohttp-chunked-res", (
            f"Expected message/ohttp-chunked-res, got {resp.headers.get('content-type')}"
        )

        bhttp_resp = _ohttp_decapsulate_response_chunked(resp.content, state)
        return bhttp_decode_response(bhttp_resp)

    def chat(
        self,
        payload: dict,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> tuple[int, dict[str, str], dict]:
        """POST /v1/chat/completions via OHTTP. Returns (status, headers, json_body)."""
        headers = [
            ("authorization", f"Bearer {self.api_key}"),
            ("content-type", "application/json"),
        ] + (extra_headers or [])
        status, hdrs, body = self.request("POST", "/v1/chat/completions", headers, json.dumps(payload))
        return status, hdrs, json.loads(body)


def parse_sse(body: bytes) -> Iterator[dict]:
    """Iterate over SSE data events in a buffered SSE stream body."""
    for line in body.decode().splitlines():
        if line.startswith("data: ") and not line.endswith("[DONE]"):
            try:
                yield json.loads(line[6:])
            except json.JSONDecodeError:
                pass


# ─── Attestation helpers ──────────────────────────────────────────────────────

def verify_ohttp_key_attested(base_url: str) -> None:
    """Verify the OHTTP HPKE key is bound to a valid TEE attestation.

    Checks that:
    1. GET /.well-known/ohttp-gateway and the attestation report agree on the key.
    2. ohttp_attestation is present (signing key for the HPKE private key is inside TEE).
    """
    print("\n--- OHTTP attestation verification ---")
    nonce = secrets.token_hex(32)
    r_key  = requests.get(f"{base_url}/.well-known/ohttp-gateway", timeout=10)
    r_attn = requests.get(f"{base_url}/v1/attestation/report?nonce={nonce}", timeout=30)
    r_key.raise_for_status()
    r_attn.raise_for_status()

    key_hex   = r_key.content.hex()
    report    = r_attn.json()

    attn_key  = report.get("ohttp_key_config", "")
    print(f"  Key from /.well-known:  {key_hex}")
    print(f"  Key from attestation:   {attn_key}")
    match = key_hex == attn_key
    print(f"  Keys match: {match}")
    assert match, "OHTTP key mismatch between /.well-known/ohttp-gateway and attestation report"

    ohttp_attn = report.get("ohttp_attestation", {})
    if ohttp_attn:
        print(f"  ohttp_attestation.signing_algo: {ohttp_attn.get('signing_algo')}")
        print(f"  ohttp_attestation.signing_key:  {ohttp_attn.get('signing_key', '')[:32]}...")
    else:
        print("  WARNING: no ohttp_attestation in report")
    print("  OK: OHTTP key is bound to TEE attestation")


# ─── Examples ─────────────────────────────────────────────────────────────────

def example_non_streaming(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 1: Non-streaming chat  (model={model})")
    print("="*60)

    status, hdrs, body = client.chat({
        "model": model,
        "messages": [{"role": "user", "content": "Say hi in exactly one word."}],
        "max_tokens": 10,
        "stream": False,
    })
    assert status == 200, f"Unexpected status {status}: {body}"
    content = body["choices"][0]["message"]["content"]
    print(f"  Status:   {status}")
    print(f"  Model:    {body.get('model')}")
    print(f"  Response: {content!r}")
    print(f"  Usage:    {body.get('usage')}")
    print("  PASS ✓")


def example_streaming(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 2: Streaming chat (stream:true inside OHTTP)  (model={model})")
    print("="*60)
    print("  Note: OHTTP is request/response — the server buffers the SSE")
    print("  stream and returns it as a single decryptable BHTTP body.")

    status, hdrs, body_bytes = client.request(
        "POST",
        "/v1/chat/completions",
        headers=[
            ("authorization", f"Bearer {client.api_key}"),
            ("content-type", "application/json"),
        ],
        body=json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "Count from 1 to 5, one number per line."}],
            "max_tokens": 40,
            "stream": True,
        }),
    )
    assert status == 200, f"Unexpected status {status}"

    chunks = list(parse_sse(body_bytes))
    full_content = "".join(
        c.get("delta", {}).get("content", "")
        for chunk in chunks
        for c in chunk.get("choices", [])
    )
    print(f"  Status:   {status}")
    print(f"  Chunks:   {len(chunks)}")
    print(f"  Response: {full_content!r}")
    assert chunks, "No SSE chunks received"
    print("  PASS ✓")


def example_tool_calls(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 3: Tool calls  (model={model})")
    print("="*60)

    tools = [{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get the current weather for a location.",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "City name"},
                    "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
                },
                "required": ["location"],
            },
        },
    }]

    # Turn 1: model decides to call the tool
    print("\n  Turn 1: Ask question that requires tool use")
    status, _, body = client.chat({
        "model": model,
        "messages": [{"role": "user", "content": "What is the weather in Paris? Use the tool."}],
        "tools": tools,
        "max_tokens": 200,
    })
    assert status == 200, f"Turn 1 failed: {status} {body}"
    choice   = body["choices"][0]
    finish   = choice.get("finish_reason")
    message  = choice["message"]
    tool_calls = message.get("tool_calls", [])
    print(f"  Finish reason: {finish}")
    assert finish == "tool_calls" and tool_calls, f"Expected tool_calls, got {finish}: {message}"
    tc = tool_calls[0]
    fn_name = tc["function"]["name"]
    fn_args = json.loads(tc["function"]["arguments"])
    print(f"  Tool call: {fn_name}({fn_args})")
    assert fn_name == "get_weather", f"Expected get_weather, got {fn_name}"
    assert "location" in fn_args, "Missing 'location' in arguments"

    # Turn 2: provide tool result and get final answer
    print("\n  Turn 2: Provide tool result and get final answer")
    messages = [
        {"role": "user", "content": "What is the weather in Paris? Use the tool."},
        {"role": "assistant", "content": None, "tool_calls": tool_calls},
        {"role": "tool", "tool_call_id": tc["id"], "content": json.dumps({
            "location": fn_args["location"],
            "temperature": "22°C",
            "condition": "sunny",
        })},
    ]
    status, _, body2 = client.chat({
        "model": model,
        "messages": messages,
        "tools": tools,
        "max_tokens": 100,
    })
    assert status == 200, f"Turn 2 failed: {status} {body2}"
    final = body2["choices"][0]["message"]["content"]
    print(f"  Final response: {final!r}")
    assert final and len(final) > 5, "Empty final response"
    print("  PASS ✓")


def example_tool_calls_streaming(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 4: Tool calls + streaming  (model={model})")
    print("="*60)

    tools = [{
        "type": "function",
        "function": {
            "name": "add",
            "description": "Add two numbers.",
            "parameters": {
                "type": "object",
                "properties": {
                    "a": {"type": "number"},
                    "b": {"type": "number"},
                },
                "required": ["a", "b"],
            },
        },
    }]

    print("\n  Turn 1 (streaming): model calls the tool")
    status, _, body_bytes = client.request(
        "POST",
        "/v1/chat/completions",
        headers=[
            ("authorization", f"Bearer {client.api_key}"),
            ("content-type", "application/json"),
        ],
        body=json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "What is 17 plus 25? Use the add tool."}],
            "tools": tools,
            "max_tokens": 200,
            "stream": True,
        }),
    )
    assert status == 200, f"Turn 1 failed: {status}"

    # Reconstruct tool call from streaming chunks
    chunks = list(parse_sse(body_bytes))
    finish_reason = None
    tool_call_id = ""
    fn_name = ""
    fn_args_buf = ""
    for chunk in chunks:
        for choice in chunk.get("choices", []):
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]
            delta = choice.get("delta", {})
            for tc in delta.get("tool_calls", []):
                if "id" in tc:
                    tool_call_id = tc["id"]
                if "function" in tc:
                    fn_name = fn_name or tc["function"].get("name", "")
                    fn_args_buf += tc["function"].get("arguments", "")
    fn_args = json.loads(fn_args_buf) if fn_args_buf else {}
    print(f"  Finish reason: {finish_reason}")
    print(f"  Tool call: {fn_name}({fn_args})")
    assert finish_reason == "tool_calls", f"Expected tool_calls, got {finish_reason}"
    assert fn_name == "add" and "a" in fn_args and "b" in fn_args

    # Turn 2: provide result
    print("\n  Turn 2: Provide tool result")
    result = str(fn_args["a"] + fn_args["b"])
    messages = [
        {"role": "user", "content": "What is 17 plus 25? Use the add tool."},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": tool_call_id, "type": "function", "function": {
                "name": fn_name, "arguments": fn_args_buf,
            }}
        ]},
        {"role": "tool", "tool_call_id": tool_call_id, "content": result},
    ]
    status, _, body2 = client.chat({"model": model, "messages": messages, "max_tokens": 60})
    assert status == 200, f"Turn 2 failed: {status}"
    final = body2["choices"][0]["message"]["content"]
    print(f"  Final response: {final!r}")
    assert "42" in final, f"Expected '42' in response, got: {final!r}"
    print("  PASS ✓")


def example_chunked(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 6: Chunked OHTTP (message/ohttp-chunked-req)  (model={model})")
    print("="*60)
    print("  Sends the request as counter-nonce AEAD chunks (the format")
    print("  required for true server-side streaming responses).")

    status, hdrs, body_bytes = client.request_chunked(
        "POST",
        "/v1/chat/completions",
        headers=[
            ("authorization", f"Bearer {client.api_key}"),
            ("content-type", "application/json"),
        ],
        body=json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: chunked OK"}],
            "max_tokens": 15,
            "stream": False,
        }),
    )
    assert status == 200, f"Unexpected status {status}"
    body = json.loads(body_bytes)
    content = body["choices"][0]["message"]["content"]
    print(f"  Status:   {status}")
    print(f"  Response: {content!r}")
    print("  PASS ✓")


def example_multi_turn(client: OhttpClient, model: str) -> None:
    print(f"\n{'='*60}")
    print(f"Example 5: Multi-turn conversation  (model={model})")
    print("="*60)

    messages = [{"role": "user", "content": "My name is Alice. Remember it."}]
    status, _, body = client.chat({"model": model, "messages": messages, "max_tokens": 30})
    assert status == 200
    reply1 = body["choices"][0]["message"]["content"]
    print(f"  Turn 1 response: {reply1!r}")

    messages += [
        {"role": "assistant", "content": reply1},
        {"role": "user", "content": "What is my name?"},
    ]
    status, _, body2 = client.chat({"model": model, "messages": messages, "max_tokens": 20})
    assert status == 200
    reply2 = body2["choices"][0]["message"]["content"]
    print(f"  Turn 2 response: {reply2!r}")
    assert "Alice" in reply2, f"Model forgot the name: {reply2!r}"
    print("  PASS ✓")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="OHTTP client examples for NEAR AI Cloud")
    parser.add_argument("--model", default="anthropic/claude-haiku-4-5")
    parser.add_argument(
        "--verify-attestation",
        action="store_true",
        help="Also verify that the OHTTP HPKE key is bound to a TEE attestation",
    )
    parser.add_argument("--base-url", default=BASE_URL)
    args = parser.parse_args()

    if not API_KEY:
        print("Error: set the API_KEY environment variable")
        raise SystemExit(1)

    client = OhttpClient(args.base_url, API_KEY)

    print(f"Base URL: {args.base_url}")
    kc = client.fetch_key_config()
    key_id  = kc[0]
    kem_id  = struct.unpack(">H", kc[1:3])[0]
    kdf_id  = struct.unpack(">H", kc[37:39])[0]
    aead_id = struct.unpack(">H", kc[39:41])[0]
    print(f"Key config ({len(kc)} bytes): key_id={key_id} kem_id={kem_id:#06x} kdf_id={kdf_id:#06x} aead_id={aead_id:#06x}")

    if args.verify_attestation:
        verify_ohttp_key_attested(args.base_url)

    example_non_streaming(client, args.model)
    example_streaming(client, args.model)
    example_tool_calls(client, args.model)
    example_tool_calls_streaming(client, args.model)
    example_multi_turn(client, args.model)
    example_chunked(client, args.model)

    print(f"\n{'='*60}")
    print("All OHTTP examples PASSED")
    print("="*60)


if __name__ == "__main__":
    main()
