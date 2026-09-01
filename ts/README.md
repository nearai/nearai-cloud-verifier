# TypeScript reference verifier

The TypeScript implementation is split by verification target:

```text
common/dstack_attestation.ts   shared quote, binding, deployment, and GPU checks
gateway/cloud_api.ts           Cloud API evidence retrieval
gateway/attestation.ts         Gateway and model attestation verification
gateway/completion.ts          signature_kind routing and response signatures
gateway/deployment_audit.ts    independent Gateway/model deployment audit
direct/                        direct model TLS and Compose Manager reports
examples/                      encrypted and OHTTP examples
```

The root [README](../README.md) explains the trust boundaries and the result of
each verification path.

## Run Gateway checks

```bash
pnpm install
export API_KEY=sk-your-api-key

# Independently audit deployments. This is not associated with a completion.
pnpm run deployment-audit -- --model deepseek-ai/DeepSeek-V3.1
pnpm run gateway-tls

# Send completions and select the verification path from signature_kind.
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

`gateway/completion.ts` keeps the original request and response bytes. Do not
parse and serialize those bytes again before the signature check.

## Run direct-endpoint checks

```bash
pnpm run model-tls -- --url https://your-model.completions.near.ai
pnpm run compose-manager -- --url https://your-model.completions.near.ai
```

These commands verify a direct endpoint's own evidence; they are not Gateway
completion verifiers. Compose Manager verifies recorded deployment actions,
not the current deployment state or a response.

## Other examples

```bash
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1
pnpm run ohttp
```

## Check the code

```bash
pnpm test
pnpm run build
```
