# NEAR AI Cloud verifier

Runnable TypeScript and Python verification examples. Pick one script for the
claim you want to check; the rest of the repository is shared implementation
for those examples.

## Setup

```bash
pnpm install
python3 -m pip install -r requirements.txt

# Required by Cloud API examples
export API_KEY=sk-your-api-key
```

## Choose an attestation example

NEAR AI Cloud exposes Gateway and model attestations separately. A signed
completion uses one of them according to its `signature_kind`. Every runnable
example is directly under `ts/` or `py/`. Each `utils/` directory contains
`attestation` (generic quote and measurement checks), `api` (evidence retrieval
and selection), and `verifier` (Gateway/model verification).

### NEAR AI Cloud

| What you want to verify | TypeScript | Python |
| --- | --- | --- |
| Gateway deployment and the TLS peer that served its attestation | `pnpm run gateway-attestation` | `python3 -m py.gateway_attestation` |
| Deployment evidence for every instance of a model | `pnpm run model-attestation -- --model deepseek-ai/DeepSeek-V3.1` | `python3 -m py.model_attestation --model deepseek-ai/DeepSeek-V3.1` |
| A signed completion and the attestation selected by its signature | `pnpm run completion -- --model deepseek-ai/DeepSeek-V3.1` | `python3 -m py.completion --model deepseek-ai/DeepSeek-V3.1` |

### Direct model endpoint

| What you want to verify | TypeScript | Python |
| --- | --- | --- |
| A model endpoint's attestation and TLS binding | `pnpm run direct-model-attestation -- --url https://your-model.completions.near.ai` | `python3 -m py.direct_model_attestation --url https://your-model.completions.near.ai` |
| Compose Manager deployment-action evidence from a model endpoint | `pnpm run direct-compose-manager-attestation -- --url https://your-model.completions.near.ai` | `python3 -m py.direct_compose_manager_attestation --url https://your-model.completions.near.ai` |

Direct endpoints only need `--token` when the endpoint requires authentication.
`BASE_URL` overrides the Cloud API base URL.

## Verify a signed Cloud completion

`completion` preserves the original request and response bytes, fetches
the completion signature, then follows its `signature_kind`:

| `signature_kind` | Verification path | Successful verification proves | It does not prove |
| --- | --- | --- | --- |
| `provider_tee` | Model evidence → model attestation → model response signature | A model-serving signer bound to verified model evidence signed these exact bytes. | Gateway TLS identity. |
| `gateway` | Gateway evidence → Gateway attestation and TLS peer → Gateway response signature | A Gateway signer bound to verified Gateway evidence signed these exact client-visible bytes. | That a model TEE generated the response. |

For `provider_tee`, send the original request with a canonical model ID and
`x-no-aliasing: true`: the model ID is part of the signed text. Do not parse
and re-serialize the request or response before verification.

A standalone Gateway or model attestation has no completion signature or
response bytes, so it cannot establish a relationship to a particular chat.

## Verify a direct model attestation

`direct_model_attestation` asks one direct endpoint for a TLS-bound report and
captures the TLS peer key on that same connection. It compares the peer with
the key in the verified quote. This is not conventional CA/hostname validation
and does not bind a later connection or a Cloud API completion.

## Other examples

- `pnpm run encrypted-chat` / `python3 -m py.encrypted_chat`: encrypted Cloud
  chat clients.
- `pnpm run ohttp` / `python3 -m py.ohttp_client`: OHTTP transport examples.
- `python3 -m py.encrypted_agent_loop`: encrypted agent-loop example.
- `python3 -m py.gateway_provenance`: Gateway image-provenance
  diagnostic. It is not part of the TEE verification result.

## Check the examples

```bash
pnpm run build

python3 -m compileall -q py
```
