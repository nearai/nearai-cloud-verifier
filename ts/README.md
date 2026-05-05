# TypeScript Verifiers

TypeScript implementations of NEAR AI Cloud cryptographic verification tools.

## Installation

```bash
npm install -g pnpm
pnpm install
```

## Usage

### Model Verification

```bash
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1 --verify-tls
```

### Chat Verification

```bash
export API_KEY=sk-your-api-key-here
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

### Encrypted Chat Verification

```bash
export API_KEY=sk-your-api-key-here
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1 --signing-algo ed25519
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1 --test-both
```

### TLS Attestation Verification

```bash
pnpm run tls -- --url https://proxy.example.com:8443
pnpm run tls -- --url https://proxy.example.com:8443 --signing-algo ed25519
```

### Domain Verification

```bash
pnpm run domain
pnpm run domain -- --model deepseek-ai/DeepSeek-V3.1
```

## Programmatic Usage

```typescript
import {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  showSigstoreProvenance,
  AttestationReport,
  IntelResult
} from './model_verifier';
import * as crypto from 'crypto';

// Generate fresh nonce
const nonce = crypto.randomBytes(32).toString('hex');

// Fetch attestation
const report = await fetchReport('deepseek-ai/DeepSeek-V3.1', nonce);

// Verify all components
const intelResult = await checkTdxQuote(report.gateway_attestation!);
checkReportData(report.gateway_attestation!, nonce, intelResult);
await checkGpu(report.model_attestations![0], nonce);
await showSigstoreProvenance(report.gateway_attestation!);
```

## Features

- 🔐 **TEE Attestation Verification** - Cryptographic proof of genuine hardware
- 🛡️ **GPU TEE Verification** - NVIDIA H100/H200 attestation via NRAS
- ✅ **Intel TDX Quote Validation** - Verify CPU TEE measurements
- 🔑 **ECDSA/Ed25519 Signature Verification** - Validate signed AI responses
- 🔒 **TLS Certificate Binding** - Prove TLS cert is held inside the TEE
- 📦 **Sigstore Provenance** - Container supply chain verification
- 🌐 **Multi-Server Support** - Load balancer attestation aggregation
