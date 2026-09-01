#!/usr/bin/env node
/**
 * Verify a signed NEAR AI Cloud completion.
 *
 * A Cloud API signature is explicitly either model-serving (`provider_tee`) or
 * Gateway (`gateway`) evidence. The kind selects both the signed text and the
 * attestation that must contain the signing identity.
 */

import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { ethers } from 'ethers';
import {
  type AttestationReport,
  type FetchedGatewayAttestation,
  fetchGatewayAttestation,
  fetchModelAttestation,
} from './cloud_api';
import {
  type VerifiedGatewayAttestation,
  type VerifiedModelAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from './attestation';
import {
  hexBytes,
  normalizeSigningAlgo,
  signingAddressBytes,
  type SigningAlgo,
} from '../common/dstack_attestation';

export type SignatureKind = 'provider_tee' | 'gateway';

export interface CompletionSignature {
  signedText: string;
  signature: string;
  signingAddress: string;
  signingAlgo: SigningAlgo;
  kind: SignatureKind;
}

export interface FetchSignatureParams {
  id: string;
  signingAlgo?: SigningAlgo;
}

export interface SignatureTextParams {
  kind: SignatureKind;
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  model?: string;
}

export interface FetchModelAttestationForSignatureParams {
  model: string;
  nonce: string;
  signature: CompletionSignature;
}

export interface FetchGatewayAttestationForSignatureParams {
  nonce: string;
  signature: CompletionSignature;
}

export interface VerifyModelResponseParams {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  signature: CompletionSignature;
  verifiedAttestation: VerifiedModelAttestation;
}

export interface VerifyGatewayResponseParams {
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  signature: CompletionSignature;
  verifiedAttestation: VerifiedGatewayAttestation;
}

export interface VerifyCompletionParams {
  id: string;
  requestBody: Uint8Array;
  responseBody: Uint8Array;
  label: string;
  signingAlgo?: SigningAlgo;
}

interface RunExampleParams {
  model: string;
  stream: boolean;
  signingAlgo?: SigningAlgo;
}

export interface ChatCompletionRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  stream: boolean;
  max_tokens: number;
}

export interface ChatCompletionResponse {
  id: string;
}

type JsonRecord = Record<string, unknown>;

type RawHttpResponse = {
  body: Buffer;
  statusCode: number;
};

function cloudApiBaseUrl(): string {
  return process.env.BASE_URL || 'https://cloud-api.near.ai';
}

function cloudApiHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const apiKey = process.env.API_KEY;
  return {
    'Accept-Encoding': 'identity',
    ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
    ...extra,
  };
}

function asRecord(value: unknown, label: string): JsonRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as JsonRecord;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function sha256Bytes(value: Uint8Array): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/**
 * Decode the public signature response. Missing `signature_kind` is rejected:
 * old records have unknown provenance and cannot safely be routed to model or
 * Gateway evidence.
 */
export function parseSignaturePayload(value: unknown): CompletionSignature {
  const record = asRecord(value, 'signature response');
  if (typeof record.error_code === 'string') {
    const message = typeof record.message === 'string' ? `: ${record.message}` : '';
    throw new Error(`Signature is unavailable (${record.error_code})${message}`);
  }
  const kind = requireString(record.signature_kind, 'signature_kind');
  if (kind !== 'provider_tee' && kind !== 'gateway') {
    throw new Error(
      `Unsupported signature_kind ${JSON.stringify(kind)}; expected provider_tee or gateway`,
    );
  }
  return {
    signedText: requireString(record.text, 'signature text'),
    signature: requireString(record.signature, 'signature'),
    signingAddress: requireString(record.signing_address, 'signing_address'),
    signingAlgo: normalizeSigningAlgo(
      requireString(record.signing_algo, 'signing_algo'),
    ),
    kind,
  };
}

/** Build the exact text that the selected signature kind must cover. */
export function signatureTextFor({
  kind,
  requestBody,
  responseBody,
  model,
}: SignatureTextParams): string {
  const requestHash = sha256Bytes(requestBody);
  const responseHash = sha256Bytes(responseBody);
  if (kind === 'gateway') {
    return `${requestHash}:${responseHash}`;
  }
  if (!model) {
    throw new Error('provider_tee signature verification needs the canonical model ID');
  }
  return `${model}:${requestHash}:${responseHash}`;
}

/** Fetch the stored signature for a completion or response ID. */
export async function fetchSignature({
  id,
  signingAlgo,
}: FetchSignatureParams): Promise<CompletionSignature> {
  const url = new URL(`/v1/signature/${encodeURIComponent(id)}`, cloudApiBaseUrl());
  if (signingAlgo !== undefined) {
    url.searchParams.set('signing_algo', signingAlgo);
  }
  const response = await fetch(url, { headers: cloudApiHeaders() });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Cloud API returned HTTP ${response.status}: ${body}`);
  }
  try {
    return parseSignaturePayload(JSON.parse(body));
  } catch (cause) {
    if (cause instanceof Error) throw cause;
    throw new Error(`Cloud API returned an invalid signature response: ${String(cause)}`);
  }
}

/** Fetch the one NEAR model attestation for a provider-TEE signature. */
export async function fetchModelAttestationForSignature({
  model,
  nonce,
  signature,
}: FetchModelAttestationForSignatureParams): Promise<AttestationReport> {
  if (signature.kind !== 'provider_tee') {
    throw new Error('Model evidence can only verify a provider_tee signature');
  }
  return fetchModelAttestation({
    model,
    nonce,
    signingAlgo: signature.signingAlgo,
    signingAddress: signature.signingAddress,
  });
}

/** Fetch Gateway evidence for a gateway-signed response. */
export async function fetchGatewayAttestationForSignature({
  nonce,
  signature,
}: FetchGatewayAttestationForSignatureParams): Promise<FetchedGatewayAttestation> {
  if (signature.kind !== 'gateway') {
    throw new Error('Gateway evidence can only verify a gateway signature');
  }
  return fetchGatewayAttestation({
    nonce,
    signingAlgo: signature.signingAlgo,
  });
}

function verifySignatureBytes(signature: CompletionSignature): void {
  if (signature.signingAlgo === 'ecdsa') {
    const declared = signingAddressBytes(signature.signingAddress, 'ecdsa');
    const signatureBytes = hexBytes(signature.signature, 'ECDSA signature');
    if (signatureBytes.length !== 65) {
      throw new Error(`ECDSA signature must be 65 bytes, got ${signatureBytes.length}`);
    }
    let recovered: string;
    try {
      recovered = ethers.utils.verifyMessage(signature.signedText, signature.signature);
    } catch (cause) {
      throw new Error(
        `ECDSA signature verification failed: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
    const matches = signingAddressBytes(recovered, 'ecdsa').equals(declared);
    console.log('ECDSA signature matches declared signer:', matches);
    if (!matches) {
      throw new Error('ECDSA signature does not match its declared signing_address');
    }
    return;
  }

  const publicKey = signingAddressBytes(signature.signingAddress, 'ed25519');
  const signedBytes = hexBytes(signature.signature, 'Ed25519 signature');
  if (signedBytes.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes, got ${signedBytes.length}`);
  }
  const spkiPrefix = Buffer.from('302a300506032b6570032100', 'hex');
  const key = crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, publicKey]),
    format: 'der',
    type: 'spki',
  });
  const valid = crypto.verify(
    null,
    Buffer.from(signature.signedText, 'utf8'),
    key,
    signedBytes,
  );
  console.log('Ed25519 signature matches declared signer:', valid);
  if (!valid) {
    throw new Error('Ed25519 signature does not match its declared signing_address');
  }
}

function verifySignatureAndEvidence(
  signature: CompletionSignature,
  expectedText: string,
  attestation: AttestationReport,
): void {
  const textMatches = signature.signedText === expectedText;
  console.log('Signature text matches request and response bytes:', textMatches);
  if (!textMatches) {
    throw new Error('Signature text does not match the request and response bytes');
  }
  verifySignatureBytes(signature);
  const algoMatches =
    attestation.signing_algo.toLowerCase() === signature.signingAlgo;
  const signerMatches = signingAddressBytes(
    attestation.signing_address,
    signature.signingAlgo,
  ).equals(signingAddressBytes(signature.signingAddress, signature.signingAlgo));
  console.log('Attestation signing algorithm matches signature:', algoMatches);
  console.log('Attestation signer matches signature:', signerMatches);
  if (!algoMatches || !signerMatches) {
    throw new Error('Signature signer does not match the verified attestation');
  }
}

/** Verify a model-serving signature against already-verified model evidence. */
export function verifyModelResponse({
  requestBody,
  responseBody,
  signature,
  verifiedAttestation,
}: VerifyModelResponseParams): void {
  if (signature.kind !== 'provider_tee') {
    throw new Error('verifyModelResponse requires a provider_tee signature');
  }
  verifySignatureAndEvidence(
    signature,
    signatureTextFor({
      kind: 'provider_tee',
      requestBody,
      responseBody,
      model: modelFromRequest(requestBody),
    }),
    verifiedAttestation.attestation,
  );
}

/** Verify a Gateway signature against already-verified Gateway evidence. */
export function verifyGatewayResponse({
  requestBody,
  responseBody,
  signature,
  verifiedAttestation,
}: VerifyGatewayResponseParams): void {
  if (signature.kind !== 'gateway') {
    throw new Error('verifyGatewayResponse requires a gateway signature');
  }
  verifySignatureAndEvidence(
    signature,
    signatureTextFor({ kind: 'gateway', requestBody, responseBody }),
    verifiedAttestation.attestation,
  );
}

function modelFromRequest(requestBody: Uint8Array): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(requestBody).toString('utf8'));
  } catch (cause) {
    throw new Error(
      `The provider_tee signature requires a JSON completion request: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
  return requireString(asRecord(parsed, 'completion request').model, 'completion request model');
}

/**
 * Verify the signature and evidence for one exact response. requestBody and
 * responseBody must be the bytes sent and received on the wire.
 */
export async function verifyCompletion({
  id,
  requestBody,
  responseBody,
  label,
  signingAlgo,
}: VerifyCompletionParams): Promise<void> {
  console.log(`\n========================================\n${label}\n========================================`);
  const signature = await fetchSignature({ id, signingAlgo });
  console.log('Signature kind:', signature.kind);
  console.log('Signature algorithm:', signature.signingAlgo);
  console.log('Signature signer:', signature.signingAddress);

  const nonce = crypto.randomBytes(32).toString('hex');
  if (signature.kind === 'provider_tee') {
    const model = modelFromRequest(requestBody);
    const attestation = await fetchModelAttestationForSignature({
      model,
      nonce,
      signature,
    });
    const verifiedAttestation = await verifyModelAttestation({ attestation, nonce });
    verifyModelResponse({ requestBody, responseBody, signature, verifiedAttestation });
    return;
  }

  const gateway = await fetchGatewayAttestationForSignature({ nonce, signature });
  const verifiedAttestation = await verifyGatewayAttestation({
    attestation: gateway.attestation,
    nonce,
    peerSpkiFingerprint: gateway.peerSpkiFingerprint,
  });
  verifyGatewayResponse({
    requestBody,
    responseBody,
    signature,
    verifiedAttestation,
  });
}

function requestBytes(
  url: URL,
  method: 'GET' | 'POST',
  headers: Record<string, string>,
  body?: Uint8Array,
): Promise<RawHttpResponse> {
  return new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http;
    const request = client.request(
      {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method,
        headers,
        timeout: 30_000,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.on('error', reject);
        response.on('end', () => {
          resolve({
            body: Buffer.concat(chunks),
            statusCode: response.statusCode ?? 500,
          });
        });
      },
    );
    request.on('error', reject);
    request.on('timeout', () => request.destroy(new Error('Cloud API request timed out')));
    if (body !== undefined) request.write(body);
    request.end();
  });
}

function completionId(responseBody: Uint8Array, stream: boolean): string {
  const text = Buffer.from(responseBody).toString('utf8');
  if (!stream) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (cause) {
      throw new Error(
        `Cloud API returned invalid completion JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
    return requireString(asRecord(parsed, 'completion response').id, 'completion response id');
  }

  for (const line of text.split('\n')) {
    if (!line.startsWith('data: ')) continue;
    const data = line.slice('data: '.length);
    if (data === '[DONE]') continue;
    try {
      const id = asRecord(JSON.parse(data), 'stream event').id;
      if (typeof id === 'string' && id.length > 0) return id;
    } catch {
      // A malformed non-ID stream line does not affect the raw bytes retained
      // for signature verification. Keep scanning for the first event ID.
    }
  }
  throw new Error('Could not find a completion ID in the stream');
}

async function runExample({ model, stream, signingAlgo }: RunExampleParams): Promise<void> {
  const request: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: 'Hello, how are you?' }],
    stream,
    max_tokens: 1,
  };
  const requestBody = Buffer.from(JSON.stringify(request), 'utf8');
  const url = new URL('/v1/chat/completions', cloudApiBaseUrl());
  const response = await requestBytes(
    url,
    'POST',
    cloudApiHeaders({
      'Content-Type': 'application/json',
      'Content-Length': String(requestBody.length),
      'x-no-aliasing': 'true',
    }),
    requestBody,
  );
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(
      `Cloud API returned HTTP ${response.statusCode}: ${response.body.toString('utf8')}`,
    );
  }
  await verifyCompletion({
    id: completionId(response.body, stream),
    requestBody,
    responseBody: response.body,
    label: stream ? 'Streaming completion' : 'Non-streaming completion',
    signingAlgo,
  });
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model =
    modelIndex !== -1 && args[modelIndex + 1]
      ? args[modelIndex + 1]
      : 'deepseek-ai/DeepSeek-V3.1';
  const algoIndex = args.indexOf('--signing-algo');
  const signingAlgo =
    algoIndex !== -1 && args[algoIndex + 1]
      ? normalizeSigningAlgo(args[algoIndex + 1]!)
      : undefined;
  if (!process.env.API_KEY) {
    throw new Error('API_KEY is required');
  }

  await runExample({ model, stream: true, signingAlgo });
  await runExample({ model, stream: false, signingAlgo });
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
