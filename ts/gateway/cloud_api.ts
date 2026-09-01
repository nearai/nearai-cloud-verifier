/**
 * Cloud API evidence retrieval and response decoding.
 *
 * This module fetches evidence only. It does not turn a response into trusted
 * evidence; callers must pass the result to the matching attestation verifier.
 */

import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import * as https from 'https';
import * as tls from 'tls';
import { URL } from 'url';

import {
  type AttestationReport,
  type SigningAlgo,
  normalizeSigningAlgo,
  signingAddressBytes,
  verifyAttestationNonce,
} from '../common/dstack_attestation';

export type { AttestationReport, SigningAlgo };

export interface AttestationApiReport {
  gateway_attestation?: AttestationReport;
  model_attestations?: AttestationReport[];
  tls_certificate?: string;
  [key: string]: unknown;
}

export interface FetchModelAttestationParams {
  model: string;
  nonce: string;
  signingAlgo: SigningAlgo;
  signingAddress: string;
}

export interface FetchModelAttestationsParams {
  model: string;
  nonce: string;
  signingAlgo?: SigningAlgo;
}

export interface FetchGatewayAttestationParams {
  nonce: string;
  signingAlgo?: SigningAlgo;
}

export interface FetchedGatewayAttestation {
  attestation: AttestationReport;
  peerSpkiFingerprint?: string;
}

type JsonRecord = Record<string, unknown>;

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

function attestationReportUrl(query: Record<string, string>): URL {
  const url = new URL('/v1/attestation/report', cloudApiBaseUrl());
  for (const [name, value] of Object.entries(query)) {
    url.searchParams.set(name, value);
  }
  return url;
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

async function requestJson(
  url: URL,
  headers: Record<string, string>,
): Promise<unknown> {
  const response = await fetch(url, { headers });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Cloud API returned HTTP ${response.status}: ${body}`);
  }
  try {
    return JSON.parse(body);
  } catch (cause) {
    throw new Error(
      `Cloud API returned invalid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
}

/**
 * Fetch JSON and capture the SPKI fingerprint of the TLS peer that served
 * that evidence response. This is intentionally Node-only: browsers do not
 * expose a peer certificate to JavaScript.
 */
function requestJsonWithPeerSpki(
  url: URL,
  headers: Record<string, string>,
): Promise<{ body: unknown; peerSpkiFingerprint?: string }> {
  if (url.protocol !== 'https:') {
    return requestJson(url, headers).then((body) => ({ body }));
  }

  return new Promise((resolve, reject) => {
    const request = https.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || 443,
        path: `${url.pathname}${url.search}`,
        method: 'GET',
        headers,
        timeout: 30_000,
      },
      (response) => {
        let peerSpkiFingerprint: string | undefined;
        try {
          const socket = response.socket as tls.TLSSocket;
          const certificate = socket.getPeerX509Certificate();
          if (certificate) {
            const spkiDer = certificate.publicKey.export({
              type: 'spki',
              format: 'der',
            });
            peerSpkiFingerprint = crypto
              .createHash('sha256')
              .update(spkiDer)
              .digest('hex');
          }
        } catch (cause) {
          reject(
            new Error(
              `Could not read the TLS peer certificate: ${
                cause instanceof Error ? cause.message : String(cause)
              }`,
            ),
          );
          response.resume();
          return;
        }

        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
        response.on('error', reject);
        response.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) >= 300) {
            reject(new Error(`Cloud API returned HTTP ${response.statusCode}: ${text}`));
            return;
          }
          try {
            resolve({ body: JSON.parse(text), peerSpkiFingerprint });
          } catch (cause) {
            reject(
              new Error(
                `Cloud API returned invalid JSON: ${
                  cause instanceof Error ? cause.message : String(cause)
                }`,
              ),
            );
          }
        });
      },
    );
    request.on('error', reject);
    request.on('timeout', () => {
      request.destroy(new Error('Cloud API request timed out'));
    });
    request.end();
  });
}

function parseAttestation(value: unknown, label: string): AttestationReport {
  const record = asRecord(value, label);
  const info = asRecord(record.info, `${label}.info`);
  if (
    record.nvidia_payload !== undefined &&
    record.nvidia_payload !== null &&
    typeof record.nvidia_payload !== 'string'
  ) {
    throw new Error(`${label}.nvidia_payload must be a string or null`);
  }
  if (
    record.tls_cert_fingerprint !== undefined &&
    record.tls_cert_fingerprint !== null &&
    typeof record.tls_cert_fingerprint !== 'string'
  ) {
    throw new Error(`${label}.tls_cert_fingerprint must be a string or null`);
  }
  return {
    intel_quote: requireString(record.intel_quote, `${label}.intel_quote`),
    signing_address: requireString(record.signing_address, `${label}.signing_address`),
    signing_algo: requireString(record.signing_algo, `${label}.signing_algo`),
    info: {
      tcb_info: info.tcb_info as AttestationReport['info']['tcb_info'],
    },
    ...(typeof record.event_log === 'string' || Array.isArray(record.event_log)
      ? { event_log: record.event_log }
      : {}),
    ...(typeof record.report_data === 'string' ? { report_data: record.report_data } : {}),
    ...(typeof record.request_nonce === 'string'
      ? { request_nonce: record.request_nonce }
      : {}),
    ...(record.nvidia_payload === null || typeof record.nvidia_payload === 'string'
      ? { nvidia_payload: record.nvidia_payload }
      : {}),
    ...(record.tls_cert_fingerprint === null || typeof record.tls_cert_fingerprint === 'string'
      ? { tls_cert_fingerprint: record.tls_cert_fingerprint }
      : {}),
    ...(typeof record.model_name === 'string' ? { model_name: record.model_name } : {}),
  };
}

function parseAttestationApiReport(value: unknown): AttestationApiReport {
  const record = asRecord(value, 'Cloud API attestation response');
  const report: AttestationApiReport = {};
  if (record.gateway_attestation !== undefined) {
    report.gateway_attestation = parseAttestation(
      record.gateway_attestation,
      'gateway_attestation',
    );
  }
  if (record.model_attestations !== undefined) {
    if (!Array.isArray(record.model_attestations)) {
      throw new Error('model_attestations must be an array when present');
    }
    report.model_attestations = record.model_attestations.map((item, index) =>
      parseAttestation(item, `model_attestations[${index}]`),
    );
  }
  if (typeof record.tls_certificate === 'string') {
    report.tls_certificate = record.tls_certificate;
  }
  return report;
}

/** Fetch the one NEAR model attestation selected by a signature signer. */
export async function fetchModelAttestation({
  model,
  nonce,
  signingAlgo,
  signingAddress,
}: FetchModelAttestationParams): Promise<AttestationReport> {
  const report = parseAttestationApiReport(
    await requestJson(
      attestationReportUrl({
        model,
        nonce,
        signing_algo: signingAlgo,
        signing_address: signingAddress,
        provider: 'near',
        include_tls_fingerprint: 'false',
      }),
      cloudApiHeaders({ 'x-no-aliasing': 'true' }),
    ),
  );
  const candidates = (report.model_attestations ?? []).filter((attestation) => {
    try {
      return (
        normalizeSigningAlgo(attestation.signing_algo) === signingAlgo &&
        signingAddressBytes(attestation.signing_address, signingAlgo).equals(
          signingAddressBytes(signingAddress, signingAlgo),
        )
      );
    } catch {
      return false;
    }
  });
  if (candidates.length !== 1) {
    throw new Error(
      `Expected exactly one NEAR model attestation for the signature signer; found ${candidates.length}`,
    );
  }
  const attestation = candidates[0]!;
  verifyAttestationNonce(attestation, nonce);
  return attestation;
}

/**
 * Fetch every NEAR model evidence item returned for a standalone deployment
 * audit. This does not associate the evidence with a completion signature.
 */
export async function fetchModelAttestations({
  model,
  nonce,
  signingAlgo,
}: FetchModelAttestationsParams): Promise<AttestationReport[]> {
  const query: Record<string, string> = {
    model,
    nonce,
    provider: 'near',
    include_tls_fingerprint: 'false',
  };
  if (signingAlgo !== undefined) query.signing_algo = signingAlgo;
  const report = parseAttestationApiReport(
    await requestJson(
      attestationReportUrl(query),
      cloudApiHeaders({ 'x-no-aliasing': 'true' }),
    ),
  );
  const attestations = report.model_attestations ?? [];
  if (attestations.length === 0) {
    throw new Error('Cloud API response does not contain model_attestations');
  }
  for (const attestation of attestations) {
    verifyAttestationNonce(attestation, nonce);
  }
  return attestations;
}

/**
 * Fetch Gateway evidence with TLS binding enabled. The peer fingerprint comes
 * from the HTTPS connection that served this evidence response, not a
 * completion request.
 */
export async function fetchGatewayAttestation({
  nonce,
  signingAlgo,
}: FetchGatewayAttestationParams): Promise<FetchedGatewayAttestation> {
  const query: Record<string, string> = {
    nonce,
    include_tls_fingerprint: 'true',
  };
  if (signingAlgo !== undefined) query.signing_algo = signingAlgo;
  const response = await requestJsonWithPeerSpki(
    attestationReportUrl(query),
    cloudApiHeaders(),
  );
  const report = parseAttestationApiReport(response.body);
  if (!report.gateway_attestation) {
    throw new Error('Cloud API response does not contain gateway_attestation');
  }
  verifyAttestationNonce(report.gateway_attestation, nonce);
  return {
    attestation: report.gateway_attestation,
    ...(response.peerSpkiFingerprint
      ? { peerSpkiFingerprint: response.peerSpkiFingerprint }
      : {}),
  };
}
