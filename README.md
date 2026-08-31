# NEAR AI Cloud Verifier

Runnable Python and TypeScript reference implementations for verifying NEAR AI
Cloud attestation evidence and signed responses. They are deliberately
independent of the SDK: use them to understand the public protocol, audit a
deployment, or port the checks to another language.

Cloud API examples require an API key:

```bash
export API_KEY=sk-your-api-key
```

## Install

```bash
# Python
python3 -m pip install -r requirements.txt

# TypeScript
pnpm install
```

## Choose a workflow

### Audit deployed evidence

The model verifier independently checks the Gateway deployment and the NEAR
model attestations returned for a model. This audits deployment evidence; it
does not bind that evidence to a particular completion.

```bash
# Python
python3 py/model_verifier.py --model deepseek-ai/DeepSeek-V3.1

# TypeScript
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1
```

The Gateway request uses a fresh nonce and requests its TLS fingerprint. The
verifier observes the TLS peer on that same evidence request and checks that
it matches the fingerprint bound into the Gateway quote. The model request
uses `provider=near`, a separate fresh nonce, and no TLS fingerprint.

### Verify a completion

The chat verifier sends one streaming and one non-streaming completion,
retains their exact request and response bytes, then fetches the corresponding
signature.

```bash
# Python
python3 py/chat_verifier.py --model deepseek-ai/DeepSeek-V3.1

# TypeScript
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

Pass `--signing-algo ecdsa` or `--signing-algo ed25519` when looking up a
specific stored signature; otherwise the Cloud API signature endpoint selects
its default.

An attestation verifies a deployment. A response signature binds exact request
and response bytes to a signing key. Cloud API returns `signature_kind` to say
which deployment evidence authorizes that key:

| `signature_kind` | Evidence verified | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | Matching NEAR model attestation | The model-serving signer signed the exact request and response bytes, and that signer is bound to verified model evidence. | Gateway TLS identity. |
| `gateway` | Gateway attestation and its observed TLS peer binding | The Gateway signer signed the exact request and response bytes, and that signer is bound to verified Gateway evidence. | That a model TEE generated the response. |

The verifier reads `signature_kind`, `signing_algo`, and `signing_address`
from `/v1/signature/{id}`. It rejects missing or unknown kinds; callers do not
choose a kind or infer one from the signed text. ECDSA and Ed25519 signatures
are both supported. Preserve the original bytes: JSON re-serialization changes
the bytes being verified.

For a `provider_tee` signature, the first component of the signed text is the
model ID in the original request. The examples send `x-no-aliasing: true` on
both the completion and model-evidence requests: it rejects aliases instead of
resolving them, so use the canonical model ID from the start.

## Checks performed

For supported NEAR evidence, the verifiers check:

- the Intel TDX quote and its accepted TCB status;
- the fresh nonce and report-data binding to the advertised signing identity;
- measured deployment data, including the app-compose measurement and RTMR3
  event-log replay;
- NVIDIA GPU evidence when an attestation provides it; and
- Gateway TLS peer binding when verifying Gateway evidence.

The scripts also print image-digest search links for troubleshooting. Those
links are diagnostic only; they are not a provenance verification step.

## Direct endpoint utilities

The following tools work with an inference endpoint's own attestation report,
rather than the Cloud API Gateway envelope:

```bash
# TypeScript
pnpm run model-tls -- --url https://your-model.completions.near.ai

# Python
python3 py/model_tls_verifier.py --url https://your-model.completions.near.ai
```

`gateway_tls_verifier` is the equivalent Gateway-TLS utility for the configured
Cloud API endpoint; run it with `pnpm run gateway-tls`. `encrypted_chat_verifier`
and the OHTTP examples are additional runnable utilities. They are not part of
the primary Cloud API model-or-Gateway verification flow described above.

## Development

```bash
pnpm test
pnpm run build
python3 -m compileall -q py
```

The TypeScript test cases focus on the public Cloud API request shapes,
signature-kind routing, nonce handling, and exact-byte signature text.
