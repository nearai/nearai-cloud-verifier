# TypeScript Verifiers

TypeScript implementations of NEAR AI Cloud cryptographic verification tools.

## Installation

```bash
npm install
```

## Usage

### Model Verification

```bash
npm run model -- --model deepseek-ai/DeepSeek-V3.1
```

### Chat Verification

```bash
export API_KEY=sk-your-api-key-here
npm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

## Programmatic Usage

```typescript
import {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  showSigstoreProvenance
} from 'nearai-cloud-verifier';

// Generate fresh nonce
const nonce = crypto.randomBytes(32).toString('hex');

// Fetch attestation
const attestation = await fetchReport('deepseek-ai/DeepSeek-V3.1', nonce);

// Verify all components
const intelResult = await checkTdxQuote(attestation);
checkReportData(attestation, nonce, intelResult);
await checkGpu(attestation, nonce);
await showSigstoreProvenance(attestation);
```

## Features

- 🔐 **TEE Attestation Verification** - Cryptographic proof of genuine hardware
- 🛡️ **GPU TEE Verification** - NVIDIA H100/H200 attestation via NRAS
- ✅ **Intel TDX Quote Validation** - Verify CPU TEE measurements
- 🔑 **ECDSA Signature Verification** - Validate signed AI responses
- 📦 **Sigstore Provenance** - Container supply chain verification
- 🌐 **Multi-Server Support** - Load balancer attestation aggregation
