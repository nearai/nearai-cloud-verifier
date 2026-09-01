# NEAR AI Cloud verifier

Runnable reference implementations for verifying NEAR AI attestation evidence.
They are organized around the endpoint you are verifying, because a Cloud API
Gateway and a direct model endpoint make different claims.

## Choose the endpoint first

| Endpoint family | What the verifier checks | What it does not establish on its own |
| --- | --- | --- |
| **NEAR AI Cloud Gateway** (`cloud-api.near.ai`) | Gateway TEE evidence, or model-serving TEE evidence returned through the Gateway. | A relationship to any particular completion. |
| **Direct model endpoint** (`*.completions.near.ai`) | The model endpoint's TEE and TLS certificate on a direct connection. | A relationship to a Cloud API completion. |
| **Direct Compose Manager report** | A recorded Compose Manager deployment action and its hash-pinned compose files. | That the action is the current deployment, or that it produced a response. |

The source tree follows those boundaries:

```text
common/                  quote, report-data, measurement, and GPU primitives
gateway/
  cloud_api              evidence retrieval and selection
  attestation            Gateway and model deployment verification
  completion             signature_kind routing and exact-byte signatures
  deployment_audit       standalone deployment audit CLI
  deployment_provenance  Gateway image provenance diagnostic (Python)
direct/
  model_tls_attestation  direct model TEE/TLS verification
  compose_manager_attestation  direct recorded-action verification
examples/                encrypted and OHTTP examples
```

TypeScript lives in [`ts`](ts); Python lives in [`py`](py). The two trees use
the same endpoint split and the same high-level verification flow.

## NEAR AI Cloud Gateway

### Audit a deployment

You can independently verify Gateway or model evidence without sending a
completion. This is useful for checking the quote, nonce freshness, measured
deployment, signing identity, and (when provided) GPU evidence. Gateway
evidence additionally binds the TLS peer observed while the evidence was
fetched.

```bash
# TypeScript
pnpm run deployment-audit -- --model deepseek-ai/DeepSeek-V3.1
pnpm run gateway-tls

# Python, from the repository root
python3 -m py.gateway.deployment_audit --model deepseek-ai/DeepSeek-V3.1
python3 -m py.gateway.tls_audit
```

These are deployment audits. They intentionally do not accept a completion
ID, request body, response body, or signature, so a successful audit does not
say anything about a particular chat.

`python3 -m py.gateway.deployment_provenance` is a separate diagnostic that
looks up the Gateway image digest in GitHub artifact attestations. It is useful
for release provenance, but is not part of the TEE verification result.

### Verify a completion

To establish a claim about one completion, preserve the exact request and
response bytes, then fetch its signature. Cloud API returns `signature_kind`;
the verifier reads that field and chooses exactly one evidence path.

```bash
# TypeScript
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1

# Python, from the repository root
python3 -m py.gateway.completion --model deepseek-ai/DeepSeek-V3.1
```

| `signature_kind` | Verification path | A successful result establishes | It does not establish |
| --- | --- | --- | --- |
| `provider_tee` | Fetch the model attestation selected by the signature signer → verify model evidence → verify the exact-byte model signature. | The model-serving signer signed these exact request/response bytes and is bound to verified model evidence. | Gateway TLS identity. |
| `gateway` | Fetch Gateway evidence → verify Gateway evidence and the observed TLS peer → verify the exact-byte Gateway signature. | The Gateway signer signed these exact client-visible request/response bytes and is bound to verified Gateway evidence. | That a model TEE executed or generated the response. |

Do not infer the kind from the signed text. It selects a different trust
boundary and different guarantee, not merely a different signer.

The high-level functions make the two paths visible in code:

```text
verifyModelAttestation
  ├─ verifyDstackQuote
  ├─ verifyReportDataBinding
  ├─ verifyDstackDeployment
  └─ verifyNvidiaEvidence

verifyGatewayAttestation
  ├─ verifyDstackQuote
  ├─ verifyReportDataBindingWithTlsFingerprint
  ├─ compare the observed TLS peer fingerprint
  └─ verifyDstackDeployment
```

After the corresponding attestation succeeds, `verifyModelResponse` or
`verifyGatewayResponse` verifies the signature over the original bytes and
checks that its signer matches the verified evidence. Re-serializing JSON or
SSE changes the bytes and invalidates this check.

## Direct model endpoint

`model_tls_attestation` requests a report directly from a model endpoint with
`include_tls_fingerprint=true`. It verifies the quote, the report-data binding
of signing identity, TLS fingerprint, and nonce, then compares the
quote-bound fingerprint with the certificate observed on that same TLS
connection.

```bash
# TypeScript
pnpm run model-tls -- --url https://your-model.completions.near.ai

# Python, from the repository root
python3 -m py.direct.model_tls_attestation \
  --url https://your-model.completions.near.ai
```

This is a direct-endpoint identity check. It does not use a Cloud API
completion signature and does not make a claim about a Gateway response.

## Direct Compose Manager report

`compose_manager_attestation` verifies the nested Compose Manager quote, a
fresh nonce, the canonical action-log hash, and the hash-pinned compose files
referenced by the recorded actions.

```bash
# TypeScript
pnpm run compose-manager -- --url https://your-model.completions.near.ai

# Python, from the repository root
python3 -m py.direct.compose_manager_attestation \
  --url https://your-model.completions.near.ai
```

It also prints GitHub artifact-attestation lookup links for reported Compose
Manager images. Those links are diagnostic only. The report is useful
deployment-transparency evidence, but its action log has no model identity or
operation outcome: it does not prove what is currently running or bind a
recorded action to an inference response.

## Install and check

```bash
pnpm install
pnpm test
pnpm run build

python3 -m pip install -r requirements.txt
python3 -m compileall -q py
```

Set `API_KEY` for Cloud API commands. Direct endpoints only need `--token` when
that endpoint requires authentication. `BASE_URL` overrides the Cloud API base
URL for the Gateway commands.
