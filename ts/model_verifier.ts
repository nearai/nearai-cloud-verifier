#!/usr/bin/env node
/**
 * A readable, independent verifier for NEAR AI Cloud attestations.
 *
 * This file intentionally does not depend on the SDK. It shows the checks a
 * client performs against the public Cloud API response: quote verification,
 * nonce and signer binding, measured deployment, and optional GPU evidence.
 */

import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import * as https from 'https';
import * as tls from 'tls';
import { URL } from 'url';
import { js_get_collateral, js_verify } from '@phala/dcap-qvl-node';

const GPU_VERIFIER_API = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
const SIGSTORE_SEARCH_BASE = 'https://search.sigstore.dev/?hash=';
const INTEL_PCCS_URL =
  'https://api.trustedservices.intel.com/tdx/certification/v4';
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

export type SigningAlgo = 'ecdsa' | 'ed25519';

export interface AttestationBaseInfo {
  intel_quote: string;
  signing_address: string;
  signing_algo: string;
  event_log?: string | unknown[];
  report_data?: string;
  request_nonce?: string;
  nvidia_payload?: string | null;
  tls_cert_fingerprint?: string | null;
  model_name?: string;
  info: {
    tcb_info?:
      | string
      | {
          app_compose?: string;
        };
  };
}

export interface AttestationReport extends AttestationBaseInfo {}

export interface AttestationApiReport {
  gateway_attestation?: AttestationReport;
  model_attestations?: AttestationReport[];
  tls_certificate?: string;
  [key: string]: unknown;
}

export interface IntelResult {
  quote: {
    body: {
      reportdata: string;
      mrconfig: string;
      rtmr3: string;
      tdattributes: string;
    };
    verified: true;
    status: string;
    advisory_ids: string[];
    debug_enabled: boolean;
    message?: string;
  };
  message?: string;
}

export interface ReportDataResult {
  binds_address: true;
  embeds_nonce: true;
  tls_fingerprint_bound: boolean;
}

export interface GpuResult {
  status: 'not_provided' | 'verified';
  verdict?: 'PASS';
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

export interface CheckReportDataParams {
  attestation: AttestationReport;
  requestNonce: string;
  intelResult: IntelResult;
  requireTlsFingerprint?: boolean;
}

export interface CheckGpuParams {
  attestation: AttestationReport;
  requestNonce: string;
}

export interface VerifyAttestationParams {
  attestation: AttestationReport;
  requestNonce: string;
  kind: 'model' | 'gateway';
  peerSpkiFingerprint?: string;
}

export interface VerifyGatewayTlsBindingParams {
  nonce?: string;
  signingAlgo?: SigningAlgo;
}

type JsonRecord = Record<string, unknown>;

type EventLogEntry = {
  digest: string;
  event: string;
  event_payload: string;
  event_type: number;
  imr: number;
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

function normalizeSigningAlgo(value: string): SigningAlgo {
  const normalized = value.toLowerCase();
  if (normalized === 'ecdsa' || normalized === 'ed25519') {
    return normalized;
  }
  throw new Error(
    `Unsupported signing algorithm ${JSON.stringify(value)}; expected ecdsa or ed25519`,
  );
}

function stripHexPrefix(value: string): string {
  return value.startsWith('0x') || value.startsWith('0X')
    ? value.slice(2)
    : value;
}

function hexBytes(value: string, label: string): Buffer {
  const normalized = stripHexPrefix(value);
  if (
    normalized.length === 0 ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]+$/.test(normalized)
  ) {
    throw new Error(`${label} must be hexadecimal bytes`);
  }
  return Buffer.from(normalized, 'hex');
}

function hexBytesOfLength(value: string, byteLength: number, label: string): Buffer {
  const bytes = hexBytes(value, label);
  if (bytes.length !== byteLength) {
    throw new Error(`${label} must be ${byteLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

function signingAddressBytes(
  signingAddress: string,
  signingAlgo: SigningAlgo,
): Buffer {
  const expectedLength = signingAlgo === 'ecdsa' ? 20 : 32;
  return hexBytesOfLength(signingAddress, expectedLength, 'signing_address');
}

function paddedSigningAddress(
  signingAddress: string,
  signingAlgo: SigningAlgo,
): Buffer {
  const address = signingAddressBytes(signingAddress, signingAlgo);
  return Buffer.concat([address, Buffer.alloc(32 - address.length)]);
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
 * Fetch JSON and, for HTTPS, capture the SPKI fingerprint of the TLS peer that
 * served that exact response. Browsers do not expose peer certificates to
 * JavaScript, so this is deliberately a Node-only helper.
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
              `Could not read the TLS peer certificate: ${cause instanceof Error ? cause.message : String(cause)}`,
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
                `Cloud API returned invalid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
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
      tcb_info: info.tcb_info as AttestationBaseInfo['info']['tcb_info'],
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

function assertNonceEcho(attestation: AttestationReport, nonce: string): void {
  const reportedNonce = hexBytesOfLength(
    requireString(attestation.request_nonce, 'attestation.request_nonce'),
    32,
    'attestation.request_nonce',
  );
  const requestedNonce = hexBytesOfLength(nonce, 32, 'requested nonce');
  const matches = reportedNonce.equals(requestedNonce);
  console.log('Attestation request_nonce matches requested nonce:', matches);
  if (!matches) {
    throw new Error('Cloud API attestation request_nonce does not match the requested nonce');
  }
}

/** Fetch exactly the NEAR model evidence bound to a completion signature. */
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
  assertNonceEcho(attestation, nonce);
  return attestation;
}

/**
 * Fetch every NEAR model evidence item Cloud API returns for a model audit.
 * This does not connect an attestation to a particular completion signature.
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
    assertNonceEcho(attestation, nonce);
  }
  return attestations;
}

/**
 * Fetch Gateway evidence with TLS fingerprint binding enabled. The returned
 * peerSpkiFingerprint is observed from the HTTPS connection that served the
 * evidence response, not from any completion request.
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
  assertNonceEcho(report.gateway_attestation, nonce);
  return {
    attestation: report.gateway_attestation,
    ...(response.peerSpkiFingerprint
      ? { peerSpkiFingerprint: response.peerSpkiFingerprint }
      : {}),
  };
}

/** Submit GPU evidence to NVIDIA NRAS. */
async function fetchNvidiaVerification(payload: unknown): Promise<unknown> {
  const response = await fetch(GPU_VERIFIER_API, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`NVIDIA NRAS returned HTTP ${response.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch (cause) {
    throw new Error(
      `NVIDIA NRAS returned invalid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
}

function quoteFieldBytes(
  record: JsonRecord,
  snakeCase: string,
  camelCase: string,
): Buffer {
  const value = record[snakeCase] ?? record[camelCase];
  if (typeof value === 'string') {
    return hexBytes(value, `verified quote ${snakeCase}`);
  }
  if (
    Array.isArray(value) &&
    value.every(
      (item) =>
        typeof item === 'number' &&
        Number.isInteger(item) &&
        item >= 0 &&
        item <= 255,
    )
  ) {
    return Buffer.from(value);
  }
  throw new Error(`verified quote ${snakeCase} is not byte data`);
}

function quoteTd10(rawResult: unknown): JsonRecord {
  const result = asRecord(rawResult, 'Intel DCAP result');
  const report = asRecord(result.report, 'Intel DCAP result.report');
  if (report.TD10 !== undefined) {
    return asRecord(report.TD10, 'Intel DCAP result.report.TD10');
  }
  if (report.TD15 !== undefined) {
    return asRecord(
      asRecord(report.TD15, 'Intel DCAP result.report.TD15').base,
      'Intel DCAP result.report.TD15.base',
    );
  }
  throw new Error('Intel DCAP result does not contain a TD10 or TD15 report');
}

/** Verify the Intel quote and expose its authenticated measurements. */
export async function checkTdxQuote(
  attestation: AttestationBaseInfo,
): Promise<IntelResult> {
  const rawQuote = hexBytes(attestation.intel_quote, 'intel_quote');
  const collateral = await js_get_collateral(INTEL_PCCS_URL, rawQuote);
  const rawResult: unknown = js_verify(
    rawQuote,
    collateral,
    BigInt(Math.floor(Date.now() / 1000)),
  );

  try {
    console.log('TDX quote verification result:', JSON.stringify(rawResult, null, 2));
  } catch {
    console.log('TDX quote verification result:', rawResult);
  }

  const result = asRecord(rawResult, 'Intel DCAP result');
  const td10 = quoteTd10(rawResult);
  const status = requireString(result.status, 'Intel DCAP result.status');
  const accepted = status === 'UpToDate' || status === 'OutOfDate';
  const tdAttributes = quoteFieldBytes(td10, 'td_attributes', 'tdAttributes');
  if (tdAttributes.length === 0) {
    throw new Error('verified quote td_attributes is empty');
  }
  const debugEnabled = (tdAttributes[0]! & 0x01) !== 0;
  const advisoryIds = Array.isArray(result.advisory_ids)
    ? result.advisory_ids.filter((value): value is string => typeof value === 'string')
    : [];

  console.log('Intel TDX quote status:', status);
  console.log('Intel TDX quote debug mode disabled:', !debugEnabled);
  if (!accepted) {
    throw new Error(
      `Intel TDX quote status ${JSON.stringify(status)} is not accepted (UpToDate and OutOfDate are accepted)`,
    );
  }
  if (debugEnabled) {
    throw new Error('Intel TDX quote has debug mode enabled');
  }

  return {
    quote: {
      body: {
        reportdata: quoteFieldBytes(td10, 'report_data', 'reportData').toString('hex'),
        mrconfig: quoteFieldBytes(td10, 'mr_config_id', 'mrConfigId').toString('hex'),
        rtmr3: quoteFieldBytes(td10, 'rt_mr3', 'rtMr3').toString('hex'),
        tdattributes: tdAttributes.toString('hex'),
      },
      verified: true,
      status,
      advisory_ids: advisoryIds,
      debug_enabled: debugEnabled,
      ...(typeof result.message === 'string' ? { message: result.message } : {}),
    },
    ...(typeof result.message === 'string' ? { message: result.message } : {}),
  };
}

/**
 * Verify the quote's signer/nonce binding. The quote is the source of truth;
 * report_data in JSON is checked only as a consistency copy.
 */
export function checkReportData({
  attestation,
  requestNonce,
  intelResult,
  requireTlsFingerprint = false,
}: CheckReportDataParams): ReportDataResult {
  assertNonceEcho(attestation, requestNonce);
  const quoteReportData = hexBytesOfLength(
    intelResult.quote.body.reportdata,
    64,
    'verified quote report_data',
  );
  const quotedNonce = quoteReportData.subarray(32, 64);
  const expectedNonce = hexBytesOfLength(requestNonce, 32, 'request nonce');
  const nonceMatches = quotedNonce.equals(expectedNonce);
  console.log('Quote report_data embeds request nonce:', nonceMatches);
  if (!nonceMatches) {
    throw new Error('Quote report_data does not embed the requested nonce');
  }

  if (attestation.report_data !== undefined) {
    const advertised = hexBytesOfLength(
      attestation.report_data,
      64,
      'attestation.report_data',
    );
    const matchesQuote = advertised.equals(quoteReportData);
    console.log('Advertised report_data matches verified quote:', matchesQuote);
    if (!matchesQuote) {
      throw new Error('attestation.report_data does not match the verified quote');
    }
  }

  const signingAlgo = normalizeSigningAlgo(attestation.signing_algo);
  const firstHalf = quoteReportData.subarray(0, 32);
  const fingerprint = attestation.tls_cert_fingerprint;
  if (fingerprint !== undefined && fingerprint !== null) {
    const fingerprintBytes = hexBytesOfLength(
      fingerprint,
      32,
      'attestation.tls_cert_fingerprint',
    );
    const expected = crypto
      .createHash('sha256')
      .update(signingAddressBytes(attestation.signing_address, signingAlgo))
      .update(fingerprintBytes)
      .digest();
    const matches = firstHalf.equals(expected);
    console.log('Quote report_data binds signing address + TLS fingerprint:', matches);
    if (!matches) {
      throw new Error(
        'Quote report_data does not bind the signing address and declared TLS fingerprint',
      );
    }
    return {
      binds_address: true,
      embeds_nonce: true,
      tls_fingerprint_bound: true,
    };
  }

  if (requireTlsFingerprint) {
    throw new Error('Gateway attestation is missing tls_cert_fingerprint');
  }

  const expected = paddedSigningAddress(attestation.signing_address, signingAlgo);
  const matches = firstHalf.equals(expected);
  console.log('Quote report_data binds signing address:', matches);
  if (!matches) {
    throw new Error('Quote report_data does not bind the signing address');
  }
  return {
    binds_address: true,
    embeds_nonce: true,
    tls_fingerprint_bound: false,
  };
}

function decodeJwtPayload(jwt: string): JsonRecord {
  const segments = jwt.split('.');
  if (segments.length < 2 || !segments[1]) {
    throw new Error('NRAS response contains an invalid JWT');
  }
  try {
    return asRecord(
      JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8')),
      'NRAS JWT payload',
    );
  } catch (cause) {
    throw new Error(
      `Could not decode NRAS JWT payload: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }
}

/** Verify model GPU evidence when the provider included it. */
export async function checkGpu({
  attestation,
  requestNonce,
}: CheckGpuParams): Promise<GpuResult> {
  const payloadText = attestation.nvidia_payload;
  if (payloadText === undefined || payloadText === null || payloadText === '') {
    console.log('GPU evidence: not provided');
    return { status: 'not_provided' };
  }
  let payload: JsonRecord;
  try {
    payload = asRecord(JSON.parse(payloadText), 'nvidia_payload');
  } catch (cause) {
    throw new Error(
      `nvidia_payload is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  const payloadNonce = requireString(payload.nonce, 'nvidia_payload.nonce');
  const nonceMatches = hexBytesOfLength(
    payloadNonce,
    32,
    'nvidia_payload.nonce',
  ).equals(hexBytesOfLength(requestNonce, 32, 'request nonce'));
  console.log('GPU payload nonce matches request nonce:', nonceMatches);
  if (!nonceMatches) {
    throw new Error('GPU payload nonce does not match the requested nonce');
  }

  const response = await fetchNvidiaVerification(payload);
  if (!Array.isArray(response)) {
    throw new Error('NRAS response must be an array');
  }
  const firstEntry = response[0];
  if (
    !Array.isArray(firstEntry) ||
    firstEntry[0] !== 'JWT' ||
    typeof firstEntry[1] !== 'string'
  ) {
    throw new Error('NRAS response does not contain an overall verdict JWT');
  }
  const verdict = decodeJwtPayload(firstEntry[1])['x-nvidia-overall-att-result'];
  const passed = verdict === true || verdict === 'PASS';
  console.log('NVIDIA attestation verdict:', verdict);
  if (!passed) {
    throw new Error(`NVIDIA NRAS rejected the GPU evidence: ${String(verdict)}`);
  }
  return { status: 'verified', verdict: 'PASS' };
}

function parseTcbInfo(attestation: AttestationBaseInfo): JsonRecord {
  const tcbInfo = attestation.info.tcb_info;
  if (typeof tcbInfo === 'string') {
    try {
      return asRecord(JSON.parse(tcbInfo), 'info.tcb_info');
    } catch (cause) {
      throw new Error(
        `info.tcb_info is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
  }
  return asRecord(tcbInfo, 'info.tcb_info');
}

/** Verify the dstack app_compose hash bound into MRCONFIGID. */
export function checkAppComposeMeasurement(
  attestation: AttestationBaseInfo,
  intelResult: IntelResult,
): void {
  const appCompose = requireString(
    parseTcbInfo(attestation).app_compose,
    'info.tcb_info.app_compose',
  );
  const mrConfig = hexBytes(intelResult.quote.body.mrconfig, 'quote mr_config_id');
  if (mrConfig.length < 33) {
    throw new Error(`quote mr_config_id must be at least 33 bytes, got ${mrConfig.length}`);
  }
  const composeHash = crypto.createHash('sha256').update(appCompose, 'utf8').digest();
  const versionMatches = mrConfig[0] === 0x01;
  const hashMatches = mrConfig.subarray(1, 33).equals(composeHash);
  console.log('\nApp compose SHA-256:', composeHash.toString('hex'));
  console.log('MRCONFIGID uses app-compose format version 1:', versionMatches);
  console.log('MRCONFIGID binds app compose:', hashMatches);
  if (!versionMatches || !hashMatches) {
    throw new Error('MRCONFIGID does not bind the attested app_compose');
  }
}

function parseEventLog(eventLog: string | unknown[] | undefined): EventLogEntry[] {
  if (eventLog === undefined) {
    throw new Error('attestation.event_log is missing');
  }
  let parsed: unknown = eventLog;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (cause) {
      throw new Error(
        `attestation.event_log is not valid JSON: ${cause instanceof Error ? cause.message : String(cause)}`,
      );
    }
  }
  if (!Array.isArray(parsed)) {
    throw new Error('attestation.event_log must be an array');
  }
  return parsed.map((item, index) => {
    const record = asRecord(item, `event_log[${index}]`);
    const eventType = record.event_type ?? 0;
    const imr = record.imr;
    if (
      typeof eventType !== 'number' ||
      !Number.isInteger(eventType) ||
      eventType < 0 ||
      eventType > 0xffff_ffff
    ) {
      throw new Error(`event_log[${index}].event_type must be an unsigned 32-bit integer`);
    }
    if (typeof imr !== 'number' || !Number.isInteger(imr)) {
      throw new Error(`event_log[${index}].imr must be an integer`);
    }
    if (typeof record.digest !== 'string') {
      throw new Error(`event_log[${index}].digest must be a string`);
    }
    return {
      digest: record.digest,
      event: typeof record.event === 'string' ? record.event : '',
      event_payload:
        typeof record.event_payload === 'string' ? record.event_payload : '',
      event_type: eventType,
      imr,
    };
  });
}

function eventDigest(entry: EventLogEntry): Buffer {
  if (entry.event_type !== DSTACK_RUNTIME_EVENT_TYPE) {
    return hexBytesOfLength(entry.digest, 48, 'event log digest');
  }
  const payload =
    entry.event_payload === ''
      ? Buffer.alloc(0)
      : hexBytes(entry.event_payload, 'runtime event payload');
  const eventType = Buffer.alloc(4);
  eventType.writeUInt32LE(DSTACK_RUNTIME_EVENT_TYPE);
  const computed = crypto
    .createHash('sha384')
    .update(eventType)
    .update(':')
    .update(entry.event)
    .update(':')
    .update(payload)
    .digest();
  if (entry.digest !== '') {
    const declared = hexBytesOfLength(entry.digest, 48, 'runtime event digest');
    if (!declared.equals(computed)) {
      throw new Error('runtime event digest does not match its event name and payload');
    }
  }
  return computed;
}

/** Replay RTMR3 so event-log metadata is linked to the verified quote. */
export function checkEventLog(
  attestation: AttestationBaseInfo,
  intelResult: IntelResult,
): void {
  const expected = hexBytesOfLength(intelResult.quote.body.rtmr3, 48, 'quote RTMR3');
  let replayed: Uint8Array = Buffer.alloc(48);
  let count = 0;
  for (const entry of parseEventLog(attestation.event_log)) {
    if (entry.imr !== 3) continue;
    count += 1;
    replayed = crypto
      .createHash('sha384')
      .update(replayed)
      .update(eventDigest(entry))
      .digest();
  }
  const matches = count > 0 && Buffer.from(replayed).equals(expected);
  console.log('RTMR3 event-log replay matches quote:', matches);
  if (!matches) {
    throw new Error(
      count === 0
        ? 'attestation.event_log has no RTMR3 events'
        : 'RTMR3 event-log replay does not match the verified quote',
    );
  }
}

/**
 * Print image-digest search links as a diagnostic convenience. This does not
 * verify image provenance and is deliberately separate from attestation
 * verification.
 */
export async function showImageDigestLookupLinks(
  attestation: AttestationBaseInfo,
): Promise<void> {
  let appCompose: string;
  try {
    appCompose = requireString(
      parseTcbInfo(attestation).app_compose,
      'info.tcb_info.app_compose',
    );
  } catch {
    return;
  }
  const digests = [...appCompose.matchAll(/@sha256:([0-9a-f]{64})/gi)].map(
    (match) => match[1]!,
  );
  if (digests.length === 0) return;
  console.log('\nImage-digest lookup links (diagnostic only):');
  for (const digest of new Set(digests)) {
    console.log(`  ${SIGSTORE_SEARCH_BASE}sha256:${digest}`);
  }
}

/**
 * Verify one Cloud API evidence item. Each failed condition throws, so a
 * printed false result can never be followed by a successful verification.
 */
export async function verifyAttestation({
  attestation,
  requestNonce,
  kind,
  peerSpkiFingerprint,
}: VerifyAttestationParams): Promise<void> {
  console.log(`\n🔐 ${kind === 'gateway' ? 'Gateway' : 'Model'} attestation`);
  console.log('Signing address:', attestation.signing_address);
  console.log('Signing algorithm:', attestation.signing_algo);
  console.log('Request nonce:', requestNonce);

  console.log('\n🔐 Intel TDX quote');
  const intelResult = await checkTdxQuote(attestation);

  console.log('\n🔐 Quote bindings');
  checkReportData({
    attestation,
    requestNonce,
    intelResult,
    requireTlsFingerprint: kind === 'gateway',
  });

  if (kind === 'gateway') {
    if (!peerSpkiFingerprint) {
      throw new Error(
        'Gateway verification needs the TLS peer fingerprint observed while fetching its attestation',
      );
    }
    const declared = hexBytesOfLength(
      requireString(
        attestation.tls_cert_fingerprint,
        'gateway_attestation.tls_cert_fingerprint',
      ),
      32,
      'gateway_attestation.tls_cert_fingerprint',
    );
    const peer = hexBytesOfLength(
      peerSpkiFingerprint,
      32,
      'observed TLS peer SPKI fingerprint',
    );
    const matches = declared.equals(peer);
    console.log('Observed TLS peer SPKI matches attested fingerprint:', matches);
    if (!matches) {
      throw new Error('Observed TLS peer SPKI fingerprint does not match gateway attestation');
    }
  }

  console.log('\n🔐 Measured deployment');
  checkEventLog(attestation, intelResult);
  checkAppComposeMeasurement(attestation, intelResult);

  if (kind === 'model') {
    console.log('\n🔐 GPU evidence');
    await checkGpu({ attestation, requestNonce });
  }

  await showImageDigestLookupLinks(attestation);
}

/** Fetch and verify Gateway evidence, including the live TLS peer binding. */
export async function verifyGatewayTlsBinding({
  nonce = crypto.randomBytes(32).toString('hex'),
  signingAlgo,
}: VerifyGatewayTlsBindingParams = {}): Promise<void> {
  const gateway = await fetchGatewayAttestation({ nonce, signingAlgo });
  await verifyAttestation({
    attestation: gateway.attestation,
    requestNonce: nonce,
    kind: 'gateway',
    peerSpkiFingerprint: gateway.peerSpkiFingerprint,
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
    throw new Error('API_KEY is required to fetch Cloud API attestations');
  }

  console.log('========================================');
  console.log('NEAR AI Cloud attestation walkthrough');
  console.log('========================================');

  const gatewayNonce = crypto.randomBytes(32).toString('hex');
  const gateway = await fetchGatewayAttestation({
    nonce: gatewayNonce,
    signingAlgo,
  });
  await verifyAttestation({
    attestation: gateway.attestation,
    requestNonce: gatewayNonce,
    kind: 'gateway',
    peerSpkiFingerprint: gateway.peerSpkiFingerprint,
  });

  const modelNonce = crypto.randomBytes(32).toString('hex');
  const modelAttestations = await fetchModelAttestations({
    model,
    nonce: modelNonce,
    signingAlgo,
  });
  for (const [index, attestation] of modelAttestations.entries()) {
    console.log(`\n========================================\nModel attestation ${index + 1}\n========================================`);
    await verifyAttestation({
      attestation,
      requestNonce: modelNonce,
      kind: 'model',
    });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
