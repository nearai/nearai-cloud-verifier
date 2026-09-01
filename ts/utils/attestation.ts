#!/usr/bin/env node
/**
 * Shared dstack attestation primitives.
 *
 * These functions verify the quote, report-data bindings, measured deployment,
 * and optional GPU evidence. Scenario files such as completion and
 * direct_model_attestation keep their different verification goals explicit.
 */

import { Buffer } from 'buffer';
import * as crypto from 'crypto';
import { js_get_collateral, js_verify } from '@phala/dcap-qvl-node';

const GPU_VERIFIER_API = 'https://nras.attestation.nvidia.com/v3/attest/gpu';
const SIGSTORE_SEARCH_BASE = 'https://search.sigstore.dev/?hash=';
const INTEL_PCCS_URL =
  'https://api.trustedservices.intel.com/tdx/certification/v4';
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

export type SigningAlgo = 'ecdsa' | 'ed25519';

/** The signer fields used to select matching attestation evidence. */
export interface SigningIdentity {
  signingAddress: string;
  signingAlgo: SigningAlgo;
}

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

export interface GpuResult {
  status: 'not_provided' | 'verified';
  verdict?: 'PASS';
}

export interface VerifyReportDataBindingParams {
  attestation: AttestationReport;
  requestNonce: string;
  intelResult: IntelResult;
}

export interface VerifyNvidiaEvidenceParams {
  attestation: AttestationReport;
  requestNonce: string;
}

type JsonRecord = Record<string, unknown>;

type EventLogEntry = {
  digest: string;
  event: string;
  event_payload: string;
  event_type: number;
  imr: number;
};

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

export function normalizeSigningAlgo(value: string): SigningAlgo {
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

export function hexBytes(value: string, label: string): Buffer {
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

export function hexBytesOfLength(value: string, byteLength: number, label: string): Buffer {
  const bytes = hexBytes(value, label);
  if (bytes.length !== byteLength) {
    throw new Error(`${label} must be ${byteLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function signingAddressBytes(
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

export function verifyAttestationNonce(attestation: AttestationReport, nonce: string): void {
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
export async function verifyDstackQuote(
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
 * Read the quote's authenticated report data and verify its nonce binding.
 * If the endpoint also exposes report_data in JSON, check it only as a
 * convenience copy against the verified quote. Direct endpoints need not
 * expose that copy.
 */
function verifiedReportData({
  attestation,
  requestNonce,
  intelResult,
}: VerifyReportDataBindingParams): Buffer {
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

  return quoteReportData;
}

/**
 * Verify the two-part report-data layout used when no TLS fingerprint is
 * requested: padded signing address || request nonce.
 */
export function verifyReportDataBinding({
  attestation,
  requestNonce,
  intelResult,
}: VerifyReportDataBindingParams): void {
  const quoteReportData = verifiedReportData({
    attestation,
    requestNonce,
    intelResult,
  });

  const signingAlgo = normalizeSigningAlgo(attestation.signing_algo);
  const firstHalf = quoteReportData.subarray(0, 32);
  const fingerprint = attestation.tls_cert_fingerprint;
  if (fingerprint !== undefined && fingerprint !== null) {
    throw new Error(
      'Attestation includes tls_cert_fingerprint; verify it with verifyReportDataBindingWithTlsFingerprint',
    );
  }

  const expected = paddedSigningAddress(attestation.signing_address, signingAlgo);
  const matches = firstHalf.equals(expected);
  console.log('Quote report_data binds signing address:', matches);
  if (!matches) {
    throw new Error('Quote report_data does not bind the signing address');
  }
}

/**
 * Verify the three-part report-data layout used when TLS binding is requested:
 * SHA-256(signing address || TLS SPKI fingerprint) || request nonce.
 * Returns the quote-bound fingerprint for the caller to compare with a live
 * TLS peer from the same evidence request.
 */
export function verifyReportDataBindingWithTlsFingerprint({
  attestation,
  requestNonce,
  intelResult,
}: VerifyReportDataBindingParams): string {
  const quoteReportData = verifiedReportData({
    attestation,
    requestNonce,
    intelResult,
  });
  const fingerprint = requireString(
    attestation.tls_cert_fingerprint,
    'attestation.tls_cert_fingerprint',
  );
  const fingerprintBytes = hexBytesOfLength(
    fingerprint,
    32,
    'attestation.tls_cert_fingerprint',
  );
  const signingAlgo = normalizeSigningAlgo(attestation.signing_algo);
  const expected = crypto
    .createHash('sha256')
    .update(signingAddressBytes(attestation.signing_address, signingAlgo))
    .update(fingerprintBytes)
    .digest();
  const matches = quoteReportData.subarray(0, 32).equals(expected);
  console.log('Quote report_data binds signing address + TLS fingerprint:', matches);
  if (!matches) {
    throw new Error(
      'Quote report_data does not bind the signing address and declared TLS fingerprint',
    );
  }
  return fingerprint;
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
export async function verifyNvidiaEvidence({
  attestation,
  requestNonce,
}: VerifyNvidiaEvidenceParams): Promise<GpuResult> {
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
 * Verify the measured dstack deployment after its quote has been verified.
 * The event log and app-compose manifest are both bound to quote measurements.
 */
export async function verifyDstackDeployment({
  attestation,
  intelResult,
}: {
  attestation: AttestationBaseInfo;
  intelResult: IntelResult;
}): Promise<void> {
  console.log('\n🔐 Measured deployment');
  checkEventLog(attestation, intelResult);
  checkAppComposeMeasurement(attestation, intelResult);
  await showImageDigestLookupLinks(attestation);
}
