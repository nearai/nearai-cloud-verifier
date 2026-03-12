#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud TEE Attestation Verifier
 * Straightforward walkthrough for checking a NEAR AI Cloud attestation.
 */

import * as crypto from 'crypto';
import { Buffer } from 'buffer';

import {
  js_verify,
  js_get_collateral,
} from "@phala/dcap-qvl-node";

const API_BASE = process.env.BASE_URL || "https://cloud-api.near.ai";
const GPU_VERIFIER_API = "https://nras.attestation.nvidia.com/v3/attest/gpu";
const SIGSTORE_SEARCH_BASE = "https://search.sigstore.dev/?hash=";

interface AttestationBaseInfo {
  intel_quote: string;
  signing_address: string;
  signing_algo: string;
  nvidia_payload: string;
  info: {
    tcb_info: string | {
      app_compose: string;
    };
  };
}

interface AttestationReport extends AttestationBaseInfo {
  model_attestations?: AttestationReport[];
  gateway_attestation?: AttestationReport;
}

interface IntelResult {
  quote: {
    body: {
      reportdata: string;
      mrconfig: string;
    };
    verified: boolean;
    message?: string;
  };
  message?: string;
}

interface NvidiaPayload {
  nonce: string;
}

interface NvidiaResponse {
  x_nvidia_overall_att_result: string;
}

interface ReportDataResult {
  binds_address: boolean;
  embeds_nonce: boolean;
}

interface GpuResult {
  nonce_matches: boolean;
  verdict: string;
}

/**
 * Make HTTP request and return JSON response
 */
async function makeRequest(url: string, options: any = {}): Promise<any> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), options.timeout || 30000);

  try {
    const response = await fetch(url, {
      method: options.method || 'GET',
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.headers || {}),
      },
      body: options.body ? (typeof options.body === 'string' ? options.body : JSON.stringify(options.body)) : undefined,
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}

/** Full API response including gateway_attestation, model_attestations, tls_certificate */
export interface AttestationApiReport {
  gateway_attestation?: AttestationReport;
  model_attestations?: AttestationReport[];
  tls_certificate?: string;
  [key: string]: unknown;
}

/**
 * Fetch attestation report from the API
 * @param includeTls - if true, appends include_tls=true (response may include tls_certificate)
 * @param signingAddress - optional; when set, narrows gateway quote to this signer
 */
async function fetchReport(
  model: string,
  nonce: string,
  signingAlgo: string = 'ecdsa',
  includeTls: boolean = false,
  signingAddress?: string,
): Promise<AttestationApiReport> {
  let url = `${API_BASE}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}&signing_algo=${signingAlgo}`;
  if (includeTls) {
    url += '&include_tls=true';
  }
  if (signingAddress) {
    url += `&signing_address=${encodeURIComponent(signingAddress)}`;
  }
  return await makeRequest(url);
}

/**
 * Submit GPU evidence to NVIDIA NRAS for verification
 */
async function fetchNvidiaVerification(payload: NvidiaPayload): Promise<any> {
  const res = await fetch(GPU_VERIFIER_API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`NRAS ${res.status}: ${text}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/**
 * Decode the payload section of a JWT token
 */
function base64urlDecodeJwtPayload(jwtToken: string): string {
  const payloadB64 = jwtToken.split('.')[1];
  const padded = payloadB64 + '='.repeat((4 - payloadB64.length % 4) % 4);
  return Buffer.from(padded, 'base64url').toString('utf-8');
}

/** report_data from intel quote body (hex string → Buffer) */
function reportDataBufferFromIntel(intelResult: IntelResult): Buffer {
  const hex = intelResult.quote.body.reportdata.replace(/^0x/i, '');
  return Buffer.from(hex, 'hex');
}

/** Signing address as 32-byte buffer (right-padded with zeros), per algo */
function signingAddressPadded32(signingAddress: string, signingAlgo: string): Buffer {
  const algo = signingAlgo.toLowerCase();
  const addrHex = algo === 'ecdsa' ? signingAddress.replace(/^0x/i, '') : signingAddress;
  const signingAddressBytes = Buffer.from(addrHex, 'hex');
  return Buffer.concat([signingAddressBytes, Buffer.alloc(32 - signingAddressBytes.length, 0)]);
}

/**
 * Cloud-api include_tls: report_data[32..64] = SHA256(nonce_32 || SHA256(pem_utf8)).
 * Returns 32-byte digest, or null if nonce is not 32 bytes.
 */
function tlsBoundNonceComponent(nonceBytes: Buffer, tlsCertificatePem: string): Buffer | null {
  if (nonceBytes.length !== 32) return null;
  const pemHash = crypto.createHash('sha256').update(Buffer.from(tlsCertificatePem, 'utf8')).digest();
  return crypto.createHash('sha256').update(nonceBytes).update(pemHash).digest();
}

function logReportDataNonceResult(
  matchesRaw: boolean,
  matchesTls: boolean,
  requestNonce: string,
  embeddedHex: string,
  expectedTlsHex: string | null,
): void {
  if (matchesRaw) {
    console.log('Report data embeds request nonce (raw):', true);
    return;
  }
  if (matchesTls) {
    console.log('Report data nonce component: TLS-bound SHA256(nonce||SHA256(pem)):', true);
    return;
  }
  console.log('Report data embeds request nonce:', false);
  console.log('  expected raw nonce:', requestNonce);
  if (expectedTlsHex) console.log('  expected TLS-bound: ', expectedTlsHex);
  console.log('  actual:            ', embeddedHex);
}

/**
 * Verify that TDX report data binds the signing address and request nonce (or TLS PEM binding).
 * When tlsCertificatePem is set, report_data[32..64] may be SHA256(nonce||SHA256(pem)) instead of raw nonce.
 */
function checkReportData(
  attestation: AttestationReport,
  requestNonce: string,
  intelResult: IntelResult,
  tlsCertificatePem?: string | null,
): ReportDataResult {
  const reportData = reportDataBufferFromIntel(intelResult);
  const signingAlgo = (attestation.signing_algo || 'ecdsa').toLowerCase();
  const expectedAddress = signingAddressPadded32(attestation.signing_address, signingAlgo);

  const embeddedAddress = reportData.subarray(0, 32);
  const embeddedNonce = reportData.subarray(32, Math.min(64, reportData.length));
  const bindsAddress = embeddedAddress.equals(expectedAddress);

  const rawNonceBytes = Buffer.from(requestNonce, 'hex');
  const matchesRaw = rawNonceBytes.length === 32 && embeddedNonce.length === 32 && embeddedNonce.equals(rawNonceBytes);
  const expectedTls =
    tlsCertificatePem && rawNonceBytes.length === 32
      ? tlsBoundNonceComponent(rawNonceBytes, tlsCertificatePem)
      : null;
  const matchesTls =
    Boolean(expectedTls) && embeddedNonce.length === 32 && embeddedNonce.equals(expectedTls!);
  const embedsNonce = matchesRaw || matchesTls;

  console.log('Signing algorithm:', signingAlgo);
  console.log('Report data binds signing address:', bindsAddress);
  if (!bindsAddress) {
    console.log('Report data binds signing address:', 'expected:', expectedAddress.toString('hex'), 'actual:', embeddedAddress.toString('hex'));
  }
  logReportDataNonceResult(
    matchesRaw,
    matchesTls,
    requestNonce,
    embeddedNonce.toString('hex'),
    expectedTls ? expectedTls.toString('hex') : null,
  );

  return { binds_address: bindsAddress, embeds_nonce: embedsNonce };
}

/**
 * Verify GPU attestation evidence via NVIDIA NRAS
 */
async function checkGpu(attestation: AttestationReport, requestNonce: string): Promise<GpuResult> {
  const payload: NvidiaPayload = JSON.parse(attestation.nvidia_payload);

  // Verify GPU uses the same request_nonce
  const nonceMatches = payload.nonce.toLowerCase() === requestNonce.toLowerCase();
  console.log('GPU payload nonce matches request_nonce:', nonceMatches);

  const body = await fetchNvidiaVerification(payload);
  const jwtToken = body[0][1];
  const verdict = JSON.parse(base64urlDecodeJwtPayload(jwtToken))['x-nvidia-overall-att-result'];
  console.log('NVIDIA attestation verdict:', verdict);

  return {
    nonce_matches: nonceMatches,
    verdict: verdict
  };
}

async function checkTdxQuote(attestation: AttestationBaseInfo): Promise<IntelResult> {
  try {
    const rawQuote = Buffer.from(attestation.intel_quote, 'hex');
    const now = BigInt(Math.floor(Date.now() / 1000));
    const pccsUrl = "https://api.trustedservices.intel.com/tdx/certification/v4";
    const quoteCollateral = await js_get_collateral(pccsUrl, rawQuote);
    const rawResult: any = js_verify(rawQuote, quoteCollateral, now);

    // Log full raw result similar to Python's to_json()
    try {
      console.log("TDX quote verification result:", JSON.stringify(rawResult, null, 2));
    } catch (_) {
      console.log("TDX quote verification result:", rawResult);
    }

    // Extract report_data and mr_config_id if present (Python parity)
    const td10 = rawResult && rawResult.report && rawResult.report.TD10 ? rawResult.report.TD10 : {};
    const reportData: string = td10.report_data || '';
    const mrConfig: string = td10.mr_config_id || '';

    // TDX status: UpToDate is ideal; OutOfDate still has valid quote crypto—do not fail verification
    const TDX_STATUS_OK = new Set(['UpToDate', 'OutOfDate']);
    const status: string | undefined = typeof rawResult?.status === 'string' ? rawResult.status : undefined;
    const verifiedFromStatus = status ? TDX_STATUS_OK.has(status) : undefined;
    const verified = verifiedFromStatus ?? Boolean(rawResult?.quote?.verified);
    if (status === 'OutOfDate') {
      // Quote still verifies; Intel marks OutOfDate when platform TCB is below
      // current advisory baseline—not a cryptographic failure.
      console.log('Intel TDX quote status: OutOfDate');
    }

    const mapped: IntelResult = {
      quote: {
        body: {
          reportdata: reportData,
          mrconfig: mrConfig,
        },
        verified,
        message: rawResult?.message,
      },
      message: rawResult?.message,
    };

    console.log('Intel TDX quote verified:', mapped.quote.verified);
    if (mapped.message) {
      console.log('Intel TDX verifier message:', mapped.message);
    }

    return mapped;
  } catch (error) {
    console.error("Verification failed:", error);
    throw error;
  }
}

/**
 * Extract all @sha256:xxx image digests and return Sigstore search links
 */
function extractSigstoreLinks(compose: string): string[] {
  if (!compose) {
    return [];
  }

  // Match @sha256:hexdigest pattern in Docker compose
  const pattern = /@sha256:([0-9a-f]{64})/g;
  const digests: string[] = [];
  let match;

  while ((match = pattern.exec(compose)) !== null) {
    digests.push(match[1]);
  }

  // Deduplicate digests while preserving order
  const seen = new Set<string>();
  const uniqueDigests: string[] = [];
  for (const digest of digests) {
    if (!seen.has(digest)) {
      seen.add(digest);
      uniqueDigests.push(digest);
    }
  }

  return uniqueDigests.map(digest => `${SIGSTORE_SEARCH_BASE}sha256:${digest}`);
}

/**
 * Check that Sigstore links are accessible (not 404)
 */
async function checkSigstoreLinks(links: string[]): Promise<Array<[string, boolean, number | string]>> {
  const results: Array<[string, boolean, number | string]> = [];
  
  for (const link of links) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      const response = await fetch(link, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
      clearTimeout(timeoutId);
      const accessible = response.status < 400;
      results.push([link, accessible, response.status]);
    } catch (error) {
      results.push([link, false, error instanceof Error ? error.message : String(error)]);
    }
  }
  
  return results;
}

/** Parsed tcb_info object with optional app_compose string (shared by Sigstore + compose display). */
function parsedTcbInfo(attestation: AttestationBaseInfo): Record<string, unknown> | null {
  const raw = attestation.info?.tcb_info;
  if (raw == null) return null;
  return typeof raw === 'string' ? (JSON.parse(raw) as Record<string, unknown>) : (raw as Record<string, unknown>);
}

async function showSigstoreProvenance(attestation: AttestationBaseInfo): Promise<void> {
  const tcbInfo = parsedTcbInfo(attestation);
  if (!tcbInfo) return;
  const compose = tcbInfo.app_compose as string | undefined;
  if (!compose) {
    return;
  }

  const sigstoreLinks = extractSigstoreLinks(compose);
  if (sigstoreLinks.length === 0) {
    return;
  }

  console.log('\n🔐 Sigstore provenance');
  console.log('Checking Sigstore accessibility for container images...');
  const linkResults = await checkSigstoreLinks(sigstoreLinks);

  for (const [link, accessible, status] of linkResults) {
    if (accessible) {
      console.log(`  ✓ ${link} (HTTP ${status})`);
    } else {
      console.log(`  ✗ ${link} (HTTP ${status})`);
    }
  }
}

/**
 * Display the Docker compose manifest and verify against mr_config from verified quote
 */
function showCompose(attestation: AttestationBaseInfo, intelResult: IntelResult): void {
  const tcbInfo = parsedTcbInfo(attestation);
  if (!tcbInfo) return;
  const appCompose = tcbInfo.app_compose as string | undefined;
  if (!appCompose) {
    return;
  }
  
  const dockerCompose = JSON.parse(appCompose).docker_compose_file;
  
  console.log('\nDocker compose manifest attested by the enclave:');
  console.log(dockerCompose);

  const composeHash = crypto.createHash('sha256').update(appCompose).digest('hex');
  console.log('Compose sha256:', composeHash);

  const mrConfig = intelResult.quote.body.mrconfig;
  console.log('mr_config (from verified quote):', mrConfig);
  const expectedMrConfig = '01' + composeHash;
  console.log('mr_config matches compose hash:', mrConfig.toLowerCase().startsWith(expectedMrConfig.toLowerCase()));
}

/**
 * Verify a single attestation.
 * @param tlsCertificatePem - when set (gateway + include_tls), verifies report_data[32..64] = SHA256(nonce||SHA256(pem))
 */
async function verifyAttestation(
  attestation: AttestationReport,
  requestNonce: string,
  verifyModel: boolean,
  tlsCertificatePem?: string | null,
): Promise<void> {
  console.log('🔐 Attestation');

  console.log('Request nonce:', requestNonce);
  // Check if signing_address exists (for both gateway and model attestations)
  if (attestation.signing_address) {
    console.log('\nSigning address:', attestation.signing_address);
  }

  console.log('\n🔐 Intel TDX quote');
  const intelResult = await checkTdxQuote(attestation);

  console.log('\n🔐 TDX report data');
  checkReportData(attestation, requestNonce, intelResult, tlsCertificatePem);

  if (verifyModel) {
    console.log('\n🔐 GPU attestation');
    await checkGpu(attestation, requestNonce);
  }

  showCompose(attestation, intelResult);
  await showSigstoreProvenance(attestation);
}

/**
 * Gateway-only verification with optional TLS PEM binding (include_tls flow).
 * Call from chat_verifier when --verify-tls; all logic lives here.
 */
async function verifyGatewayTlsBinding(
  signingAddress: string,
  model: string,
  signingAlgo: string = 'ecdsa',
): Promise<void> {
  const requestNonce = crypto.randomBytes(32).toString('hex');
  const report = await fetchReport(model, requestNonce, signingAlgo, true, signingAddress);
  const gateway = report.gateway_attestation;
  const tlsPem = report.tls_certificate;

  if (!gateway) {
    console.log('No gateway_attestation in report (cannot verify TLS binding).');
    return;
  }
  if (!tlsPem) {
    console.log(
      'TLS verification requested but response has no tls_certificate ' +
        '(set INGRESS_TLS_CERT_PATH on cloud-api or omit --verify-tls).',
    );
    return;
  }

  console.log('========================================');
  console.log('🔐 Gateway attestation (include_tls)');
  console.log('========================================');
  await verifyAttestation(gateway, requestNonce, false, tlsPem);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'deepseek-ai/DeepSeek-V3.1';
  const includeTls = args.includes('--verify-tls');

  const requestNonce = crypto.randomBytes(32).toString('hex');
  const report = await fetchReport(model, requestNonce, 'ecdsa', includeTls);

  if (!report.gateway_attestation) {
    console.log('No gateway attestation found');
    return;
  }

  console.log('========================================');
  console.log('🔐 Gateway attestation');
  console.log('========================================');
  await verifyAttestation(
    report.gateway_attestation,
    requestNonce,
    false,
    includeTls ? report.tls_certificate : undefined,
  );

  // Verify model attestations
  if (!report.model_attestations) {
    console.log('No model attestations found');
    return;
  }

  let idx = 0;
  for (const modelAttestation of report.model_attestations) {
    idx += 1;
    console.log('\n\n\n========================================');
    console.log(`🔐 Model attestations: (#${idx})`);
    console.log('========================================');
    await verifyAttestation(modelAttestation, requestNonce, true);
  }
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  fetchReport,
  verifyGatewayTlsBinding,
  checkTdxQuote,
  checkReportData,
  checkGpu,
  verifyAttestation,
  showSigstoreProvenance,
  showCompose,
  AttestationBaseInfo,
  AttestationReport,
  IntelResult,
  ReportDataResult,
  GpuResult
};
