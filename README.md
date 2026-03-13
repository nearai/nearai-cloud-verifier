# NEAR AI Cloud Verifier

**Cryptographic Verification Tools for NEAR AI Cloud TEE-Protected AI**

Python and TypeScript tools for validating NEAR AI Cloud attestation reports and response signatures. These verifiers provide cryptographic proof that your AI requests are processed in genuine Trusted Execution Environments (TEE) with hardware-enforced privacy.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8+-blue.svg)](https://www.typescriptlang.org/)

## 🌟 Features

- 🔐 **TEE Attestation Verification** - Cryptographic proof of genuine hardware
- 🛡️ **GPU TEE Verification** - NVIDIA H100/H200 attestation via NRAS
- ✅ **Intel TDX Quote Validation** - Verify CPU TEE measurements
- 🔑 **ECDSA Signature Verification** - Validate signed AI responses
- 📦 **Sigstore Provenance** - Container supply chain verification
- 🌐 **Domain Verification** - Gateway TLS attestation vs live certificate (default)
- 🔗 **Multi-Server Support** - Load balancer attestation aggregation

## 📋 Requirements

- Get NEAR AI Cloud API key from [cloud.near.ai](https://cloud.near.ai)

### Python
- Python 3.10+
- `requests`, `eth-account`, `dcap-qvl`, `cryptography`

### TypeScript
- Node.js 20+
- TypeScript 5.8+
- `ethers` for cryptographic operations
- `tsx` for TypeScript execution
- `dcap-qvl-node` for verifying TDX quotes

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/nearai-cloud/nearai-cloud-verifier.git
cd nearai-cloud-verifier

# For Python
pip install -r requirements.txt

# For TypeScript
npm install -g pnpm
pnpm install
```

### Model Verification

```bash
export API_KEY=sk-your-api-key-here

# Python
python3 py/model_verifier.py --model deepseek-ai/DeepSeek-V3.1
python3 py/model_verifier.py --model deepseek-ai/DeepSeek-V3.1 --verify-tls

# TypeScript
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1 --verify-tls
```

### Chat Verification

```bash
export API_KEY=sk-your-api-key-here

# Python
python3 py/chat_verifier.py --model deepseek-ai/DeepSeek-V3.1

# TypeScript
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1

# Optional: TLS PEM binding is implemented in model_verifier (gateway); chat_verifier only calls it when --verify-tls
python3 py/chat_verifier.py --model deepseek-ai/DeepSeek-V3.1 --verify-tls
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1 --verify-tls
```

### Encrypted Chat Verification

```bash
export API_KEY=sk-your-api-key-here

# Python - Test ECDSA encryption
python3 py/encrypted_chat_verifier.py --model deepseek-ai/DeepSeek-V3.1

# Python - Test both ECDSA and Ed25519
python3 py/encrypted_chat_verifier.py --model deepseek-ai/DeepSeek-V3.1 --test-both

# TypeScript - Test ECDSA encryption
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1

# TypeScript - Test both algorithms
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1 --test-both
```

### Domain Verification (gateway TLS)

**Default behavior** for `domain_verifier`: confirms the gateway’s attested TLS material matches what the host serves on **:443**.

1. `GET /v1/attestation/report?include_tls_fingerprint=true` → `tls_certificate` + `gateway_attestation` (with `tls_cert_fingerprint`)
2. Gateway `report_data` must bind that PEM (`model_verifier.verify_attestation`)
3. **Leaf** SHA256(DER) fingerprint must match the live server certificate

```bash
export BASE_URL=https://cloud-api.near.ai   # optional; hostname defaults --domain

python3 py/domain_verifier.py
pnpm run domain

# Optional: --domain host --signing-address 0x... --model ...
```

If the report has no `tls_certificate`, configure `TLS_CERT_PATH` on cloud-api.

## 🔐 Model Verifier

### Model Attestations

Generates a fresh nonce, requests a new attestation, and verifies:
- **GPU attestation**: Submits GPU evidence payload to NVIDIA NRAS and verifies the nonce matches
- **TDX report data**: Validates that report data binds the signing key (ECDSA or Ed25519) and nonce
- **Intel TDX quote**: Verifies TDX quote with [`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) library
- **Compose manifest**: Displays Docker compose manifest and verifies it matches the mr_config measurement

### Gateway Attestations

The model verifier also verifies the private inference gateway for
- **TDX report data**: Validates that report data includes the nonce in request
- **Intel TDX quote**: Verifies TDX quote with [`dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) library
- **Compose manifest**: Displays Docker compose manifest and verifies it matches the mr_config measurement


### Usage

```bash
# Python
python3 py/model_verifier.py [--model MODEL_NAME]

# TypeScript
pnpm run model -- [--model MODEL_NAME]
```

**Default model**: `deepseek-ai/DeepSeek-V3.1`

The verifier fetches attestations from the `/v1/attestation/report` endpoint. No API key is required for this endpoint.

### Example Output for Gateway Attestation

```
========================================
🔐 Gateway attestation
========================================

Request nonce: abc123...

🔐 TDX report data
Signing algorithm: ecdsa
Report data binds signing address: True
Report data embeds request nonce: True

🔐 Intel TDX quote
Intel TDX quote verified: True

Docker compose manifest attested by the enclave:
services:
  cloud-api:
    image: nearaidev/cloud-api@sha256:xxxxx
    ...

Compose sha256: abc123...
mr_config (from verified quote): 0x01abc123...
mr_config matches compose hash: True

🔐 Sigstore provenance
Checking Sigstore accessibility for container images...
  ✓ https://search.sigstore.dev/?hash=sha256:c63f9... (HTTP 200)
```

### Example Output for Model Attestation

```
========================================
🔐 Model attestations: (#1)
========================================

Signing address: 0x1234...
Request nonce: abc123...

🔐 TDX report data
Signing algorithm: ecdsa
Report data binds signing address: True
Report data embeds request nonce: True

🔐 GPU attestation
GPU payload nonce matches request_nonce: True
NVIDIA attestation verdict: PASS

🔐 Intel TDX quote
Intel TDX quote verified: True

Docker compose manifest attested by the enclave:
version: '3.8'
services:
  model:
    image: deepseek@sha256:77fbe5f...
    ...

Compose sha256: abc123...
mr_config (from verified quote): 0x01abc123...
mr_config matches compose hash: True

🔐 Sigstore provenance
Checking Sigstore accessibility for container images...
  ✓ https://search.sigstore.dev/?hash=sha256:77fbe5f... (HTTP 200)
```

### What It Verifies

- ✅ **GPU TEE Measurements** - Proves genuine NVIDIA H100/H200 TEE
- ✅ **Model Hash** - Verifies exact model version
- ✅ **Code Hash** - Confirms inference code integrity
- ✅ **Nonce Freshness** - Prevents replay attacks
- ✅ **Cryptographic Binding** - Signing key bound to hardware
- ✅ **Container Provenance** - Verifies build supply chain

## 🔑 Chat Verifier

Fetches chat completions (streaming and non-streaming), verifies ECDSA signatures, and validates attestations:

1. Sends chat completion request to `/v1/chat/completions`
2. Fetches signature from `/v1/signature/{chat_id}` endpoint
3. Verifies request hash and response hash match the signed hashes
4. Recovers ECDSA signing address from signature
5. Fetches fresh attestation with user-supplied nonce for the recovered signing address
6. Validates attestation using the same checks as attestation verifier

**Note**: The verifier supplies a fresh nonce when fetching attestation (step 5), which ensures attestation freshness but means the nonce/report_data won't match the original signing context. This is expected behavior - the verifier proves the signing key is bound to valid hardware, not that a specific attestation was used for signing.

### Setup

Set your API key as an environment variable:

```bash
export API_KEY=sk-your-api-key-here
```

Or create a `.env` file:

```bash
API_KEY=sk-your-api-key-here
```

Then run:

```bash
# Python
python3 py/model_verifier.py [--model MODEL_NAME]

# TypeScript
pnpm run model -- [--model MODEL_NAME]
```

**Default model**: `deepseek-ai/DeepSeek-V3.1`

### What It Verifies

- ✅ **Request Body Hash** - Matches server-computed hash
- ✅ **Response Text Hash** - Matches server-computed hash
- ✅ **ECDSA Signature** - Valid and recovers to claimed signing address
- ✅ **Signing Address Binding** - Bound to hardware via TDX report data
- ✅ **GPU Attestation** - Passes NVIDIA verification
- ✅ **Intel TDX Quote** - Valid CPU TEE measurements

## 🔐 Encrypted Chat Verifier

Tests end-to-end encryption for chat completions. Encrypts request messages and decrypts response content using ECDSA or Ed25519 signing algorithms.

### Setup

Set your API key as an environment variable:

```bash
export API_KEY=sk-your-api-key-here
```

### Usage

```bash
# Python - Test with ECDSA (default)
python3 py/encrypted_chat_verifier.py --model deepseek-ai/DeepSeek-V3.1

# Python - Test with Ed25519
python3 py/encrypted_chat_verifier.py --model deepseek-ai/DeepSeek-V3.1 --signing-algo ed25519

# Python - Test both algorithms
python3 py/encrypted_chat_verifier.py --model deepseek-ai/DeepSeek-V3.1 --test-both

# TypeScript - Test with ECDSA (default)
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1

# TypeScript - Test with Ed25519
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1 --signing-algo ed25519

# TypeScript - Test both algorithms
pnpm run encrypted-chat -- --model deepseek-ai/DeepSeek-V3.1 --test-both
```

**Default model**: `deepseek-ai/DeepSeek-V3.1`

### What It Tests

- ✅ **End-to-End Encryption** - Request messages encrypted with model's public key
- ✅ **Response Decryption** - Response content decrypted with client's private key
- ✅ **ECDSA Encryption** - ECIES (Elliptic Curve Integrated Encryption Scheme) with AES-GCM
- ✅ **Ed25519 Encryption** - X25519 key exchange with ChaCha20-Poly1305
- ✅ **Streaming Support** - Decrypts streaming responses in real-time
- ✅ **Non-Streaming Support** - Decrypts complete non-streaming responses

### Encryption Headers

The verifier automatically includes the following headers for encrypted requests:

- `X-Signing-Algo`: Either `ecdsa` or `ed25519`
- `X-Client-Pub-Key`: Client's public key in hex format
- `X-Model-Pub-Key`: Model's public key from attestation report

## 🌐 Domain Verifier

Gateway TLS verification runs **by default** every time you run the domain verifier.

| Step | What it does |
|------|----------------|
| 1 | `GET /v1/attestation/report?include_tls_fingerprint=true` (optional `signing_address`) |
| 2 | `verify_attestation(gateway, …, tls_certificate_pem)` — `report_data` must bind the PEM |
| 3 | Leaf cert in `tls_certificate` must match live `:443` (SHA256 fingerprint) |

### Usage

```bash
export BASE_URL=https://cloud-api.near.ai   # optional

python3 py/domain_verifier.py
pnpm run domain
```

### Requirements

- ✅ Gateway `report_data` binds `tls_certificate`
- ✅ Same leaf cert served on the domain over TLS

### Example Output

```
========================================
🔐 Domain TLS vs attestation report
========================================
Domain: cloud-api.near.ai

🔐 Gateway attestation (include_tls_fingerprint binding)
...
🔐 Live TLS certificate vs attested tls_certificate
Fetching certificate from live server: cloud-api.near.ai:443
Fingerprints match: True
```

## 📦 Sigstore Provenance

Both scripts automatically extract all container image digests from the Docker compose manifest (matching `@sha256:xxx` patterns) and verify Sigstore accessibility for each image. This allows you to:

1. Verify the container images were built from the expected source repository
2. Review the GitHub Actions workflow that built the images
3. Audit the build provenance and supply chain metadata

The verifiers check each Sigstore link with an HTTP HEAD request to ensure provenance data is available (not 404).

### Example Output

```
🔐 Sigstore provenance
Checking Sigstore accessibility for container images...
  ✓ https://search.sigstore.dev/?hash=sha256:77fbe5f... (HTTP 200)
  ✓ https://search.sigstore.dev/?hash=sha256:abc123... (HTTP 200)
```

If a link returns ✗, the provenance data may not be available in Sigstore (either the image wasn't signed or the digest is incorrect).

## 🌐 Multi-Server Load Balancer Setup

In production deployments with multiple backend servers behind a load balancer:

### Server Behavior

- Each server has its own unique signing key/address
- Attestation requests with `signing_address` parameter return 404 if the address doesn't match
- Response includes `model_attestations: [attestation]` (single-element array with this server's attestation)

### Load Balancer Requirements

When `/v1/attestation/report?signing_address={addr}&nonce={nonce}`:

1. **Broadcast** the request to all backend servers
2. Collect non-404 responses from servers matching the signing_address
3. Merge `model_attestations` arrays from all responses
4. Return combined response with all servers' attestations

### Verifier Flow

1. Get signature → extract `signing_address`
2. Request attestation with `signing_address` parameter
3. LB broadcasts → collect attestations from all servers
4. Verifier finds matching attestation by comparing `signing_address` in `model_attestations`

### Example Response (Multi-Server)

```json
{
  "signing_address": "0xServer1...",
  "intel_quote": "...",
  "model_attestations": [
    {"signing_address": "0xServer1...", "intel_quote": "...", ...},
    {"signing_address": "0xServer2...", "intel_quote": "...", ...}
  ]
}
```

The verifier filters `model_attestations` to find the entry matching the signature's `signing_address`.

## 🔬 Verification Architecture

**TEE-Protected Inference**
- Model weights in GPU TEE (NVIDIA H100/H200)
- Inference computation in GPU secure enclaves
- Complete end-to-end protection
- Verified via GPU attestation + signature verification

## 🛡️ Trust Model

### You Must Trust

- ✅ NVIDIA GPU vendor (H100/H200 TEE correctness)
- ✅ Intel CPU vendor (TDX implementation)

### You Do NOT Need to Trust

- ❌ Model operators
- ❌ Cloud provider (AWS, GCP, Azure)
- ❌ System administrators
- ❌ Other users on same hardware

### Cryptographic Guarantees

- ✅ **Hardware-Enforced Privacy** - Data never leaves TEE in plaintext
- ✅ **Verifiable Execution** - Cryptographic proof of code integrity
- ✅ **Tamper-Proof** - Cannot be modified by operators or admins
- ✅ **Auditable** - Full attestation reports for every request

## 📖 Usage Examples

### Basic Model Verification

```bash
# Python - Verify confidential model
python3 py/model_verifier.py

# Python - Verify specific model
python3 py/model_verifier.py --model deepseek-ai/DeepSeek-V3.1

# TypeScript - Verify default model
pnpm run model

# TypeScript - Verify specific model
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1
```

### Chat Verification with Custom Model

```bash
export API_KEY=sk-your-api-key-here

# Python
python3 py/chat_verifier.py --model deepseek-ai/DeepSeek-V3.1

# TypeScript
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
```

### Domain Verification

```bash
export BASE_URL=https://your-domain.near.ai

python3 py/domain_verifier.py
pnpm run domain
```

### Programmatic Usage

#### Python

```python
from model_verifier import fetch_report, check_tdx_quote, check_gpu, check_report_data
import secrets

# Generate fresh nonce
nonce = secrets.token_hex(32)

# Fetch attestation
attestation = fetch_report("deepseek-ai/DeepSeek-V3.1", nonce)

# Verify all components
intel_result = await check_tdx_quote(attestation)
check_report_data(attestation, nonce, intel_result)
# With include_tls_fingerprint / tls_certificate: pass PEM so nonce component SHA256(nonce||SHA256(pem)) is accepted
# check_report_data(attestation, nonce, intel_result, tls_certificate_pem)
check_gpu(attestation, nonce)
```

#### TypeScript

```typescript
import {
  fetchReport,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  showSigstoreProvenance,
  AttestationReport,
  IntelResult
} from 'nearai-cloud-verifier';
import * as crypto from 'crypto';

// Generate fresh nonce
const nonce = crypto.randomBytes(32).toString('hex');

// Fetch attestation
const attestation: AttestationReport = await fetchReport('deepseek-ai/DeepSeek-V3.1', nonce);

// Verify all components
const intelResult: IntelResult = await checkTdxQuote(attestation);
checkReportData(attestation, nonce, intelResult);
// With include_tls_fingerprint: pass tlsCertificatePem as 4th arg so SHA256(nonce||SHA256(pem)) is accepted
// checkReportData(attestation, nonce, intelResult, tlsCertificatePem);
await checkGpu(attestation, nonce);
await showSigstoreProvenance(attestation);
```

## 🔗 Integration

### With NEAR AI Cloud Gateway

These verifiers work with [NEAR AI Cloud Gateway](https://github.com/nearai/cloud-api) attestation endpoints:

- `GET /v1/attestation/report` - TEE attestation; use `include_tls_fingerprint=true` for domain verifier (`signing_address` optional)
- `GET /v1/signature/{chat_id}` - Get response signature

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test with both Python and TypeScript verifiers:

```bash
# Test Python verifiers
python3 py/model_verifier.py --model deepseek-ai/DeepSeek-V3.1
python3 py/chat_verifier.py --model deepseek-ai/DeepSeek-V3.1
python3 py/domain_verifier.py

# Test TypeScript verifiers
pnpm run model -- --model deepseek-ai/DeepSeek-V3.1
pnpm run chat -- --model deepseek-ai/DeepSeek-V3.1
pnpm run domain
```

5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Attribution

Built with:
- [NVIDIA NRAS](https://nras.attestation.nvidia.com) - GPU TEE attestation service
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) - CPU TEE technology
- [Sigstore](https://www.sigstore.dev/) - Container supply chain verification

Powered by [NEAR AI Cloud](https://github.com/nearai/cloud-api)
