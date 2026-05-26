#!/usr/bin/env python3
"""End-to-end encrypted agent-loop demo for NEAR AI Cloud.

Drives a single `/v1/chat/completions` request that asks the model to use
the server-side `web_context_search` tool and decrypts every encrypted
field on the wire so the full agent loop is visible in plaintext.

What this exercises
-------------------

1.  E2EE handshake (Ed25519 + HKDF-SHA256 + XChaCha20-Poly1305 — protocol
    version 2). The client encrypts its prompt with the model's attested
    public key; the server inside the CVM decrypts it, runs the model,
    runs the agent loop, and encrypts every chunk it streams back with
    the client's public key.

2.  Server-side `web_context_search` agent loop. When the request carries
    `tools: [{"type":"web_context_search"}]`, the inference-proxy
    detects it, rewrites it into a regular function tool for the model,
    runs Brave's LLM Context search inside the CVM whenever the model
    asks for it, and splices the result back into the SSE stream as a
    synthetic `delta.nearai_tool_result` chunk. The next iteration the
    model produces a grounded answer. All of this stays inside the
    attested perimeter; the client only ever sees ciphertext on the wire.

3.  Output decoding. Every encrypted field — `delta.content`,
    `delta.reasoning_content`, `delta.tool_calls[].function.{name,arguments}`,
    `delta.nearai_tool_result.output` — is decrypted in real time and
    printed so a customer can see what the model actually did and what
    Brave actually returned.

Required headers
----------------

The agent loop needs four headers for the full encrypted path:

    X-Signing-Algo: ed25519
    X-Client-Pub-Key: <hex of client's Ed25519 public key>
    X-Encryption-Version: 2          # HKDF + XChaCha20 (v1 has a known
                                       client-side cipher mismatch and is
                                       not recommended for this path)
    X-Encrypt-All-Fields: true       # encrypts tool_calls.function fields
                                       and tools[].function.{name,description,parameters}

Usage
-----

    export API_KEY=sk-...
    python3 py/encrypted_agent_loop_verifier.py --model zai-org/GLM-5.1-FP8

    # Custom prompt:
    python3 py/encrypted_agent_loop_verifier.py \
        --model zai-org/GLM-5.1-FP8 \
        --prompt 'What was the most recent SpaceX launch? Use web_context_search.'

    # Against staging:
    BASE_URL=https://cloud-stg-api.near.ai \
        python3 py/encrypted_agent_loop_verifier.py --model zai-org/GLM-5.1-FP8

The script exits 0 on a clean agent-loop completion, 1 otherwise.
"""

import argparse
import json
import os
import sys
from typing import Optional

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings

API_KEY = os.environ.get("API_KEY", "")
BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai").rstrip("/")


# ── attestation pub-key fetch ──────────────────────────────────────


def fetch_model_signing_pub_key(model: str, signing_algo: str = "ed25519") -> str:
    """Pull the model's signing public key from its attestation report.

    The cloud-api report aggregates per-backend attestations in
    `model_attestations[]`; we take the first one for the requested
    algorithm. The hex string returned here is the **Ed25519 signing
    public key** — internally we convert it to its X25519 equivalent
    via libsodium's `crypto_sign_ed25519_pk_to_curve25519` to do ECDH.
    """
    url = f"{BASE_URL}/v1/attestation/report?model={model}&signing_algo={signing_algo}"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {API_KEY}"},
        timeout=30,
    )
    resp.raise_for_status()
    report = resp.json()
    for att in report.get("model_attestations") or []:
        if att.get("signing_public_key"):
            return att["signing_public_key"]
    # Some deployments expose the report directly without the aggregation
    # wrapper (e.g. calling inference-proxy through model-proxy with a
    # proxy admin token). Fall back to the top-level fields.
    if report.get("signing_public_key") and report.get("signing_algo") == signing_algo:
        return report["signing_public_key"]
    raise RuntimeError(
        f"no signing_public_key for model={model} algo={signing_algo} in attestation report"
    )


# ── client keypair ─────────────────────────────────────────────────


def generate_client_ed25519_keypair():
    """Fresh Ed25519 keypair for this request only.

    Returns `(private_key_obj, public_key_hex)`. The private key never
    leaves this process; only the public key goes on the wire as the
    `X-Client-Pub-Key` header.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes.hex()


# ── v2 encryption (X25519 + HKDF-SHA256 + XChaCha20-Poly1305) ──────
#
# Both halves of the protocol live below: `encrypt_to_server` is what
# the client uses to wrap its prompt with the server's pub key;
# `decrypt_from_server` unwraps each chunk the server streams back,
# which the proxy encrypted with this client's pub key.
#
# Wire format is the same in both directions:
#   [ephemeral_x25519_pub (32)] [nonce (24)] [ciphertext + poly1305 tag]
# encoded as hex.


def _hkdf_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ed25519_encryption",
    ).derive(shared_secret)


def encrypt_to_server(plaintext: bytes, server_ed25519_pub_hex: str) -> bytes:
    server_x25519_pub = bindings.crypto_sign_ed25519_pk_to_curve25519(
        bytes.fromhex(server_ed25519_pub_hex)
    )
    ephem_priv = os.urandom(32)
    ephem_pub = bindings.crypto_scalarmult_base(ephem_priv)
    shared = bindings.crypto_scalarmult(ephem_priv, server_x25519_pub)
    key = _hkdf_key(shared)
    nonce = os.urandom(24)
    ct = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, None, nonce, key)
    return ephem_pub + nonce + ct


def decrypt_from_server(blob: bytes, client_priv_key_obj) -> bytes:
    if len(blob) < 32 + 24 + 16:
        raise ValueError("ciphertext too short for v2")
    ephem_pub, nonce, ct = blob[:32], blob[32:56], blob[56:]
    seed = client_priv_key_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = client_priv_key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x25519_secret = bindings.crypto_sign_ed25519_sk_to_curve25519(seed + pub)
    shared = bindings.crypto_scalarmult(x25519_secret, ephem_pub)
    key = _hkdf_key(shared)
    return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, key)


def try_decrypt(blob_hex: Optional[str], client_priv) -> Optional[str]:
    """Decrypt if `blob_hex` looks like ciphertext; otherwise return None.

    Used to skip fields the server didn't encrypt (e.g. metadata, status
    enums, identifiers) without surfacing decryption errors as failures.
    """
    if not isinstance(blob_hex, str) or not blob_hex:
        return None
    if len(blob_hex) % 2 != 0 or not all(c in "0123456789abcdefABCDEF" for c in blob_hex):
        return None
    try:
        return decrypt_from_server(bytes.fromhex(blob_hex), client_priv).decode()
    except Exception:
        return None


# ── streaming agent-loop demo ──────────────────────────────────────


DEFAULT_PROMPT = (
    "How deep is the Mediterranean Sea? Use the web_context_search tool and cite a source."
)


def run(model: str, prompt: str, max_tokens: int) -> int:
    """Returns process exit code (0 = clean tool round-trip, 1 otherwise)."""
    print(f"BASE_URL = {BASE_URL}")
    print(f"MODEL    = {model}")
    print(f"PROMPT   = {prompt!r}")
    print()

    server_pub = fetch_model_signing_pub_key(model, "ed25519")
    print(f"[+] server ed25519 pub: {server_pub[:24]}…")

    client_priv, client_pub_hex = generate_client_ed25519_keypair()
    print(f"[+] client ed25519 pub: {client_pub_hex[:24]}… (private key kept locally)")

    encrypted_prompt = encrypt_to_server(prompt.encode("utf-8"), server_pub).hex()
    print(f"[+] encrypted prompt: {len(encrypted_prompt)} hex chars on the wire")

    request_body = {
        "model": model,
        "stream": True,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": encrypted_prompt}],
        "tools": [{"type": "web_context_search"}],
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        # ── E2EE ──
        "X-Signing-Algo": "ed25519",
        "X-Client-Pub-Key": client_pub_hex,
        "X-Encryption-Version": "2",
        # ── Encrypt every sensitive field, not just `content`. Required for
        #   the agent-loop path so that the model-generated tool-call arguments
        #   (which contain the search query the model derived from the user's
        #   E2EE-decrypted prompt) and the tool result chunks don't appear
        #   plaintext on the wire.
        "X-Encrypt-All-Fields": "true",
    }

    print()
    print(f"[+] POST {BASE_URL}/v1/chat/completions  (streaming)")
    resp = requests.post(
        f"{BASE_URL}/v1/chat/completions",
        json=request_body,
        headers=headers,
        stream=True,
        timeout=180,
    )
    print(f"[+] HTTP {resp.status_code}")
    if resp.status_code != 200:
        try:
            print(json.dumps(resp.json(), indent=2))
        except ValueError:
            print(resp.text[:1000])
        return 1
    print()
    print("=" * 70)
    print("STREAM (decrypted in place)")
    print("=" * 70)

    chat_id: Optional[str] = None
    iterations = 0
    saw_tool_call_name = False
    saw_tool_result = False
    accumulated_args = ""
    accumulated_content = ""

    for raw in resp.iter_lines():
        if not raw:
            continue
        line = raw.decode()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload == "[DONE]":
            print("\n\n[DONE]")
            break
        try:
            chunk = json.loads(payload)
        except json.JSONDecodeError:
            continue
        if chat_id is None:
            chat_id = chunk.get("id")

        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or {}

            # Model's reasoning (encrypted under X-Encrypt-All-Fields).
            for fld in ("reasoning_content", "reasoning"):
                blob = delta.get(fld)
                if blob:
                    decoded = try_decrypt(blob, client_priv)
                    if decoded is not None and accumulated_content == "":
                        # Only print the first few characters of reasoning
                        # so the transcript stays readable.
                        snippet = decoded.replace("\n", " ")[:60]
                        print(f"[{fld}] {snippet}…", flush=True)

            # Model's final-answer content (encrypted by default whenever
            # an encryption context is active).
            blob = delta.get("content")
            if blob:
                decoded = try_decrypt(blob, client_priv)
                if decoded is not None:
                    accumulated_content += decoded
                    print(decoded, end="", flush=True)

            # Model's tool-call deltas (function.{name,arguments} encrypted
            # under X-Encrypt-All-Fields).
            for tc in delta.get("tool_calls") or []:
                fn = tc.get("function") or {}
                if fn.get("name"):
                    decoded = try_decrypt(fn["name"], client_priv)
                    if decoded is not None and not saw_tool_call_name:
                        print(f"\n[tool_call.name decrypted] {decoded}")
                        saw_tool_call_name = True
                if fn.get("arguments"):
                    decoded = try_decrypt(fn["arguments"], client_priv)
                    if decoded is not None:
                        accumulated_args += decoded
                        print(decoded, end="", flush=True)

            # Proxy's synthetic `nearai_tool_result` chunk — the Brave
            # grounding the model sees on the next iteration.
            tr = delta.get("nearai_tool_result")
            if tr:
                saw_tool_result = True
                output_blob = tr.get("output")
                output_decoded = try_decrypt(output_blob, client_priv) if output_blob else None
                print()
                print()
                print("─" * 70)
                print(
                    f"[nearai_tool_result] tool_call_id={tr.get('tool_call_id')} "
                    f"name={tr.get('name')} status={tr.get('status')}"
                )
                if output_decoded is not None:
                    preview = output_decoded[:800]
                    print(f"[output decrypted, {len(output_decoded)} chars]")
                    print(preview)
                    if len(output_decoded) > len(preview):
                        print(f"… ({len(output_decoded) - len(preview)} more chars)")
                else:
                    print("[output NOT decrypted — looks plaintext or invalid hex]")
                    print(repr(output_blob)[:300])
                print("─" * 70)

            fr = choice.get("finish_reason")
            if fr:
                iterations += 1
                print()
                print(f"[iteration {iterations} finish_reason={fr}]")

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"chat_id              : {chat_id}")
    print(f"iterations           : {iterations}")
    print(f"saw tool_call name?  : {saw_tool_call_name}")
    print(f"accumulated args     : {accumulated_args!r}")
    print(f"saw nearai_tool_result?: {saw_tool_result}")
    print(f"final content chars  : {len(accumulated_content)}")
    print()
    if saw_tool_result and saw_tool_call_name and accumulated_content:
        print(f"✅ Agent loop fired end-to-end against {BASE_URL} with full E2EE")
        return 0
    print("⚠ Did not observe a complete encrypted tool round-trip.")
    if not saw_tool_call_name:
        print("   - No decrypted tool_call name. Possible causes:")
        print("     • Cloud-api is still stripping the web_context_search tool")
        print("       (needs PR nearai/cloud-api#676 deployed).")
        print("     • Model decided not to call the tool — try a more")
        print("       explicit prompt or increase --max-tokens.")
    if saw_tool_call_name and not saw_tool_result:
        print("   - Tool was invoked but no synthetic result chunk arrived.")
        print("     Check that the CVM has WEB_CONTEXT_SEARCH_URL +")
        print("     WEB_CONTEXT_SEARCH_API_KEY env vars set and that")
        print("     egress to api.search.brave.com is permitted.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "End-to-end encrypted agent-loop demo for NEAR AI Cloud "
            "(web_context_search tool, Ed25519 + v2 encryption)."
        )
    )
    parser.add_argument(
        "--model",
        default="zai-org/GLM-5.1-FP8",
        help=(
            "Model identifier. Currently only GLM-5.1-FP8 has the "
            "web_context_search tool enabled in production."
        ),
    )
    parser.add_argument(
        "--prompt",
        default=DEFAULT_PROMPT,
        help="User prompt to send (encrypted before leaving this machine).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=600,
        help="Max output tokens. Reasoning models need at least a few hundred.",
    )
    args = parser.parse_args()

    if not API_KEY:
        print("error: API_KEY environment variable is required", file=sys.stderr)
        print("  export API_KEY=sk-...", file=sys.stderr)
        return 2

    return run(args.model, args.prompt, args.max_tokens)


if __name__ == "__main__":
    sys.exit(main())
