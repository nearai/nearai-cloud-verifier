#!/usr/bin/env node
/**
 * Verify Compose Manager deployment-transparency evidence from a direct model
 * endpoint. This is intentionally separate from the Cloud API model/Gateway
 * flows: compose_manager_attestation is only exposed by a direct report.
 *
 * The nested quote binds SHA-256(canonical actions JSON) || client nonce. Each
 * compose action can in turn pin a file in nearai/cvm-compose-files by commit
 * and SHA-256. This verifies a recorded deployment action, not that a model is
 * currently running that compose file: the action log has no model identity or
 * successful-operation outcome.
 */

import { Buffer } from 'buffer';
import * as crypto from 'crypto';

import {
  checkEventLog,
  verifyDstackQuote,
  type AttestationBaseInfo,
} from '../common/dstack_attestation';

type JsonRecord = Record<string, unknown>;

export interface VerifyComposeManagerAttestationParams {
  url: string;
  signingAlgo?: string;
  token?: string;
}

interface ComposeManagerAttestation {
  actions: unknown[];
  actionsHash: string;
  nonce: string;
  nonceSource?: string;
  quote: string;
  eventLog: string | unknown[];
  reportData: string;
}

interface ComposeFileRecord {
  actionIndex: number;
  commit: string;
  file: string;
  fileSha256: string;
}

function asRecord(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
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

function hexBytes(value: string, label: string): Buffer {
  const normalized = value.startsWith('0x') || value.startsWith('0X')
    ? value.slice(2)
    : value;
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

function canonicalJson(value: unknown, label: string): unknown {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`${label} must not contain a non-finite number`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => canonicalJson(item, `${label}[${index}]`));
  }
  const record = asRecord(value, label);
  const canonical: JsonRecord = {};
  for (const key of Object.keys(record).sort()) {
    canonical[key] = canonicalJson(record[key], `${label}.${key}`);
  }
  return canonical;
}

/**
 * Compose Manager hashes compact UTF-8 JSON with every object key sorted.
 * Null fields and empty service arrays are omitted by Compose Manager before
 * this function sees the response, so the response is serialized as-is.
 */
export function canonicalActionsJson(actions: unknown[]): string {
  const serialized = JSON.stringify(canonicalJson(actions, 'actions'));
  if (serialized === undefined) {
    throw new Error('Could not serialize Compose Manager actions');
  }
  return serialized;
}

export function composeManagerActionsHash(actions: unknown[]): string {
  return crypto
    .createHash('sha256')
    .update(canonicalActionsJson(actions), 'utf8')
    .digest('hex');
}

function parseComposeManagerAttestation(value: unknown): ComposeManagerAttestation {
  const record = asRecord(value, 'compose_manager_attestation');
  if (!Array.isArray(record.actions)) {
    throw new Error('compose_manager_attestation.actions must be an array');
  }
  const eventLog = record.event_log;
  if (typeof eventLog !== 'string' && !Array.isArray(eventLog)) {
    throw new Error('compose_manager_attestation.event_log must be a JSON array or string');
  }
  return {
    actions: record.actions,
    actionsHash: requireString(record.actions_hash, 'compose_manager_attestation.actions_hash'),
    nonce: requireString(record.nonce, 'compose_manager_attestation.nonce'),
    ...(typeof record.nonce_source === 'string' ? { nonceSource: record.nonce_source } : {}),
    quote: requireString(record.quote, 'compose_manager_attestation.quote'),
    eventLog,
    reportData: requireString(record.report_data, 'compose_manager_attestation.report_data'),
  };
}

function directReportUrl(endpoint: string, nonce: string, signingAlgo?: string): URL {
  const base = new URL(endpoint);
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new Error('URL must use http:// or https://');
  }
  const report = new URL('/v1/attestation/report', base);
  report.searchParams.set('nonce', nonce);
  if (signingAlgo !== undefined) {
    report.searchParams.set('signing_algo', signingAlgo);
  }
  return report;
}

async function fetchComposeManagerAttestation({
  url,
  nonce,
  signingAlgo,
  token,
}: {
  url: string;
  nonce: string;
  signingAlgo?: string;
  token?: string;
}): Promise<ComposeManagerAttestation> {
  const headers: Record<string, string> = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const reportUrl = directReportUrl(url, nonce, signingAlgo);
  const response = await fetch(reportUrl, { headers });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Direct attestation endpoint returned HTTP ${response.status}: ${body}`);
  }
  let envelope: unknown;
  try {
    envelope = JSON.parse(body);
  } catch (cause) {
    throw new Error(
      `Direct attestation endpoint returned invalid JSON: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
    );
  }
  const record = asRecord(envelope, 'direct attestation response');
  return parseComposeManagerAttestation(record.compose_manager_attestation);
}

function quoteAttestation(attestation: ComposeManagerAttestation): AttestationBaseInfo {
  return {
    intel_quote: attestation.quote,
    signing_address: '',
    signing_algo: '',
    info: { tcb_info: {} },
    event_log: attestation.eventLog,
  };
}

function composeFileRecords(actions: unknown[]): ComposeFileRecord[] {
  const records: ComposeFileRecord[] = [];
  for (const [index, value] of actions.entries()) {
    const action = asRecord(value, `actions[${index}]`);
    if (typeof action.file_sha256 !== 'string') {
      continue;
    }
    records.push({
      actionIndex: index,
      commit: requireString(action.commit, `actions[${index}].commit`),
      file: requireString(action.file, `actions[${index}].file`),
      fileSha256: requireString(action.file_sha256, `actions[${index}].file_sha256`),
    });
  }
  return records;
}

function uniqueComposeFileRecords(records: ComposeFileRecord[]): ComposeFileRecord[] {
  const unique = new Map<string, ComposeFileRecord>();
  for (const record of records) {
    const key = `${record.commit}\u0000${record.file}\u0000${record.fileSha256}`;
    unique.set(key, record);
  }
  return [...unique.values()];
}

function requireComposeFileRecords(records: ComposeFileRecord[]): ComposeFileRecord[] {
  const unique = uniqueComposeFileRecords(records);
  if (unique.length === 0) {
    throw new Error('Compose Manager action log has no hash-pinned compose files');
  }
  return unique;
}

function composeSourceUrl(record: ComposeFileRecord): URL {
  if (!/^[0-9a-fA-F]{40}$/.test(record.commit)) {
    throw new Error(`actions[${record.actionIndex}].commit must be a 40-character Git commit`);
  }
  const segments = record.file.split('/');
  if (segments.length === 0 || segments.some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error(`actions[${record.actionIndex}].file must be a repository-relative path`);
  }
  const encodedPath = segments.map((segment) => encodeURIComponent(segment)).join('/');
  return new URL(
    `https://raw.githubusercontent.com/nearai/cvm-compose-files/${record.commit}/${encodedPath}`,
  );
}

async function verifyComposeFile(record: ComposeFileRecord): Promise<void> {
  const expected = hexBytesOfLength(
    record.fileSha256,
    32,
    `actions[${record.actionIndex}].file_sha256`,
  );
  const sourceUrl = composeSourceUrl(record);
  const response = await fetch(sourceUrl);
  if (!response.ok) {
    throw new Error(
      `Could not fetch ${record.file} at ${record.commit} from cvm-compose-files: HTTP ${response.status}`,
    );
  }
  const actual = crypto.createHash('sha256').update(Buffer.from(await response.arrayBuffer())).digest();
  const matches = actual.equals(expected);
  console.log(`Compose file SHA-256 matches (${record.file} @ ${record.commit}):`, matches);
  if (!matches) {
    console.log('  expected:', expected.toString('hex'));
    console.log('  actual:  ', actual.toString('hex'));
    throw new Error(`Pinned compose file hash does not match ${record.file} at ${record.commit}`);
  }
}

function showComposeManagerImageLookup(actions: unknown[]): void {
  const images = new Set<string>();
  for (const [index, value] of actions.entries()) {
    const action = asRecord(value, `actions[${index}]`);
    if (action.action === 'compose_manager_started' && typeof action.image === 'string') {
      images.add(action.image);
    }
  }
  if (images.size === 0) {
    return;
  }
  console.log('\nGitHub artifact-attestation lookup (diagnostic only):');
  for (const image of images) {
    const match = /^nearaidev\/compose-manager@sha256:([0-9a-f]{64})$/i.exec(image);
    if (match) {
      console.log(
        `  https://api.github.com/repos/nearai/compose-manager/attestations/sha256:${match[1]}`,
      );
    } else {
      console.log(`  Compose Manager reported image: ${image}`);
    }
  }
}

/**
 * Verify direct Compose Manager evidence and all selected hash-pinned compose
 * files. Every unique commit/file/hash tuple in the returned action log is
 * checked. The report does not attest a current action, so the verifier never
 * chooses one as a model-specific deployment claim.
 */
export async function verifyComposeManagerAttestation({
  url,
  signingAlgo,
  token,
}: VerifyComposeManagerAttestationParams): Promise<void> {
  const nonce = crypto.randomBytes(32).toString('hex');
  console.log('Request nonce:', nonce);
  const attestation = await fetchComposeManagerAttestation({
    url,
    nonce,
    signingAlgo,
    token,
  });

  const requestedNonce = hexBytesOfLength(nonce, 32, 'request nonce');
  const reportedNonce = hexBytesOfLength(
    attestation.nonce,
    32,
    'compose_manager_attestation.nonce',
  );
  const nonceMatches = reportedNonce.equals(requestedNonce);
  console.log('Compose Manager nonce matches request:', nonceMatches);
  if (!nonceMatches) {
    throw new Error('compose_manager_attestation.nonce does not match the requested nonce');
  }
  if (attestation.nonceSource) {
    console.log('Compose Manager nonce source:', attestation.nonceSource);
  }

  const computedActionsHash = Buffer.from(composeManagerActionsHash(attestation.actions), 'hex');
  const advertisedActionsHash = hexBytesOfLength(
    attestation.actionsHash,
    32,
    'compose_manager_attestation.actions_hash',
  );
  const actionsMatch = computedActionsHash.equals(advertisedActionsHash);
  console.log('Canonical actions SHA-256 matches actions_hash:', actionsMatch);
  if (!actionsMatch) {
    console.log('  expected:', advertisedActionsHash.toString('hex'));
    console.log('  actual:  ', computedActionsHash.toString('hex'));
    throw new Error('compose_manager_attestation.actions do not match actions_hash');
  }

  console.log('\n🔐 Compose Manager Intel TDX quote');
  const quoteAttestationValue = quoteAttestation(attestation);
  const intelResult = await verifyDstackQuote(quoteAttestationValue);
  const quotedReportData = hexBytesOfLength(
    intelResult.quote.body.reportdata,
    64,
    'verified Compose Manager quote report_data',
  );
  const advertisedReportData = hexBytesOfLength(
    attestation.reportData,
    64,
    'compose_manager_attestation.report_data',
  );
  const reportDataMatchesQuote = advertisedReportData.equals(quotedReportData);
  console.log('Advertised report_data matches verified quote:', reportDataMatchesQuote);
  if (!reportDataMatchesQuote) {
    throw new Error('compose_manager_attestation.report_data does not match the verified quote');
  }
  const expectedReportData = Buffer.concat([computedActionsHash, requestedNonce]);
  const reportDataBindingMatches = quotedReportData.equals(expectedReportData);
  console.log('Quote binds actions_hash + request nonce:', reportDataBindingMatches);
  if (!reportDataBindingMatches) {
    throw new Error('Compose Manager quote does not bind actions_hash and the requested nonce');
  }

  console.log('\n🔐 Compose Manager event log');
  checkEventLog(quoteAttestationValue, intelResult);

  const records = requireComposeFileRecords(composeFileRecords(attestation.actions));
  console.log(`\n🔐 Hash-pinned compose files (${records.length})`);
  for (const record of records) {
    await verifyComposeFile(record);
  }
  showComposeManagerImageLookup(attestation.actions);

  console.log(
    '\n✓ Compose Manager deployment-transparency evidence passed. ' +
      'This verifies recorded actions, not the current deployment state or an inference response.',
  );
}

function optionValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index !== -1 ? args[index + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const url = optionValue(args, '--url');
  if (!url) {
    throw new Error(
      'Usage: pnpm run compose-manager -- --url https://your-model.completions.near.ai ' +
        '[--signing-algo ecdsa|ed25519] [--token TOKEN]',
    );
  }

  console.log('========================================');
  console.log('🔐 Compose Manager deployment transparency');
  console.log('========================================');
  console.log(`Target: ${url}`);
  await verifyComposeManagerAttestation({
    url,
    signingAlgo: optionValue(args, '--signing-algo'),
    token: optionValue(args, '--token') ?? process.env.API_KEY,
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
