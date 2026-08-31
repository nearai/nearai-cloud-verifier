# TypeScript verifiers

These are runnable, dependency-light reference implementations. The root
[README](../README.md) explains the Cloud API model, Gateway, and signed
response workflows.

## Install

```bash
pnpm install
export API_KEY=sk-your-api-key
```

## Cloud API workflows

```bash
# Audit Gateway evidence and the returned NEAR model attestations.
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1

# Send streaming and non-streaming completions, then verify their signatures
# against the evidence selected by signature_kind.
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

`chat_verifier.ts` preserves the raw request and response bytes. Do not replace
those bytes with JSON that has been parsed and serialized again.

## Other utilities

```bash
# Verify the TLS peer binding on a direct model endpoint.
pnpm run model-tls -- --url https://your-model.completions.near.ai

# Encrypted-completion example.
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1

# Gateway-TLS and OHTTP examples.
pnpm run gateway-tls
pnpm run ohttp
```

The direct-endpoint tools use that endpoint's report format. They are separate
from the Cloud API Gateway envelope used by `model` and `chat`.

## Check the reference code

```bash
pnpm test
pnpm run build
```
