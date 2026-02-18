#!/usr/bin/env node
/**
 * TLS Certificate Verification for NEAR AI Inference Proxy
 *
 * Verifies that an inference proxy's TLS connection terminates inside the TEE
 * by checking that the live TLS certificate's SPKI hash is bound into the
 * Intel TDX attestation quote.
 *
 * How it works:
 *   1. Connects to the inference proxy and fetches an attestation report with
 *      `include_tls_fingerprint=true`. This causes the proxy to include its
 *      TLS certificate's SPKI hash in the TDX report data.
 *   2. Verifies the Intel TDX quote via dcap-qvl.
 *   3. Checks that report_data[0..32] = SHA256(signing_address || spki_hash),
 *      binding the signing key AND the TLS certificate to the TEE.
 *   4. Connects to the same server via TLS and extracts the live certificate's
 *      SPKI hash (SHA256 of SubjectPublicKeyInfo DER bytes).
 *   5. Verifies the live SPKI hash matches the attested tls_cert_fingerprint.
 *
 * This proves the TLS certificate is held by the TEE — trust comes from the
 * hardware attestation, not from Certificate Authority trust chains.
 *
 * Usage:
 *   pnpm run tls -- --url https://proxy.example.com:8443
 *   pnpm run tls -- --url https://proxy.example.com --signing-algo ed25519
 */

import * as crypto from 'crypto';
import * as tls from 'tls';
import { Buffer } from 'buffer';

import {
  checkTdxQuote,
  checkGpu,
  checkRtmrs,
  showCompose,
  showSigstoreProvenance,
  AttestationBaseInfo,
  IntelResult,
} from './model_verifier';

interface TlsAttestationReport extends AttestationBaseInfo {
  tls_cert_fingerprint?: string;
  signing_public_key?: string;
  request_nonce?: string;
}

/**
 * Connect to a server via TLS and compute the SHA-256 hash of the leaf
 * certificate's Subject Public Key Info (SPKI) DER encoding.
 *
 * This matches the inference proxy's `compute_spki_hash()` function which
 * hashes the SPKI (not the full certificate), making the hash stable across
 * certificate renewals that reuse the same key.
 */
function fetchLiveSpkiHash(hostname: string, port: number = 443): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, hostname, {
      servername: hostname,
      rejectUnauthorized: false, // Trust comes from TEE binding, not CA
    });

    let resolved = false;

    socket.on('secureConnect', () => {
      if (resolved) return;
      resolved = true;

      try {
        const cert = socket.getPeerX509Certificate();
        if (!cert) {
          socket.end();
          reject(new Error('Failed to get certificate from server'));
          return;
        }
        socket.end();

        // Export SPKI DER and compute SHA-256 — matches inference proxy's compute_spki_hash()
        const spkiDer = cert.publicKey.export({ type: 'spki', format: 'der' });
        const hash = crypto.createHash('sha256').update(spkiDer).digest('hex');
        resolve(hash);
      } catch (error) {
        socket.end();
        reject(error);
      }
    });

    socket.on('error', (error) => {
      if (resolved) return;
      resolved = true;
      reject(new Error(`TLS connection failed: ${error.message}`));
    });

    socket.setTimeout(10000, () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      reject(new Error('TLS connection timeout'));
    });
  });
}

/**
 * Fetch attestation report from an inference proxy with TLS fingerprint included.
 * The endpoint is public on proxies with the latest build. For older deployments
 * that still require auth, pass a bearer token via --token.
 */
async function fetchAttestationReport(
  baseUrl: string,
  nonce: string,
  signingAlgo: string = 'ecdsa',
  token?: string,
): Promise<TlsAttestationReport> {
  const url = `${baseUrl}/v1/attestation/report?include_tls_fingerprint=true&nonce=${nonce}&signing_algo=${signingAlgo}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 60000);

  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(url, { signal: controller.signal, headers });
    clearTimeout(timeoutId);

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`HTTP ${response.status}: ${text}`);
    }

    return await response.json() as TlsAttestationReport;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error('Attestation request timed out');
    }
    throw error;
  }
}

/**
 * Verify that the TDX report data binds the signing address, TLS certificate
 * fingerprint, and request nonce.
 *
 * Report data layout (64 bytes):
 *   [0..32]  = SHA256(signing_address_bytes || cert_fingerprint_bytes)
 *   [32..64] = nonce
 */
function checkReportDataWithTls(
  attestation: TlsAttestationReport,
  requestNonce: string,
  intelResult: IntelResult,
): { binds_address_and_tls: boolean; embeds_nonce: boolean } {
  const reportDataHex = intelResult.quote.body.reportdata;
  const reportData = Buffer.from(reportDataHex.replace('0x', ''), 'hex');
  const signingAlgo = (attestation.signing_algo || 'ecdsa').toLowerCase();

  // Parse signing address bytes
  let signingAddressBytes: Buffer;
  if (signingAlgo === 'ecdsa') {
    signingAddressBytes = Buffer.from(attestation.signing_address.replace('0x', ''), 'hex');
  } else {
    signingAddressBytes = Buffer.from(attestation.signing_address, 'hex');
  }

  const embeddedFirst32 = reportData.subarray(0, 32);
  const embeddedNonce = reportData.subarray(32);

  // Verify first 32 bytes: SHA256(signing_address || cert_fingerprint)
  const certFpBytes = Buffer.from(attestation.tls_cert_fingerprint!, 'hex');
  const expected = crypto.createHash('sha256')
    .update(signingAddressBytes)
    .update(certFpBytes)
    .digest();

  const bindsAddressAndTls = embeddedFirst32.equals(expected);
  console.log('Report data binds signing address + TLS fingerprint:', bindsAddressAndTls);
  if (!bindsAddressAndTls) {
    console.log('  expected:', expected.toString('hex'));
    console.log('  actual:  ', embeddedFirst32.toString('hex'));
  }

  // Verify last 32 bytes: nonce
  const embedsNonce = embeddedNonce.toString('hex') === requestNonce;
  console.log('Report data embeds request nonce:', embedsNonce);
  if (!embedsNonce) {
    console.log('  expected:', requestNonce);
    console.log('  actual:  ', embeddedNonce.toString('hex'));
  }

  return {
    binds_address_and_tls: bindsAddressAndTls,
    embeds_nonce: embedsNonce,
  };
}

/**
 * Main verification flow: prove that a proxy's TLS cert is bound to the TEE.
 */
async function verifyTlsAttestation(url: string, signingAlgo: string = 'ecdsa', token?: string): Promise<void> {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') {
    throw new Error('URL must use https:// scheme for TLS verification');
  }
  const hostname = parsed.hostname;
  const port = parsed.port ? parseInt(parsed.port, 10) : 443;
  const baseUrl = url.replace(/\/+$/, '');

  // 1. Generate nonce
  const requestNonce = crypto.randomBytes(32).toString('hex');
  console.log('Request nonce:', requestNonce);

  // 2. Fetch attestation report with TLS fingerprint
  console.log(`\nFetching attestation from ${baseUrl} ...`);
  const attestation = await fetchAttestationReport(baseUrl, requestNonce, signingAlgo, token);

  if (!attestation.tls_cert_fingerprint) {
    throw new Error(
      'Attestation report does not include tls_cert_fingerprint. ' +
      'The proxy may not have TLS_CERT_PATH configured.'
    );
  }

  console.log('Signing address:', attestation.signing_address);
  console.log('Signing algorithm:', attestation.signing_algo);
  console.log('Attested TLS SPKI fingerprint:', attestation.tls_cert_fingerprint);

  // 3. Verify Intel TDX quote
  console.log('\n🔐 Intel TDX quote');
  const intelResult = await checkTdxQuote(attestation);

  // 4. Verify report data binds signing address + TLS fingerprint + nonce
  console.log('\n🔐 TDX report data (TLS mode)');
  checkReportDataWithTls(attestation, requestNonce, intelResult);

  // 5. Fetch live certificate SPKI hash and compare
  console.log('\n🔐 Live TLS certificate');
  console.log(`Connecting to ${hostname}:${port} ...`);
  const liveSpkiHash = await fetchLiveSpkiHash(hostname, port);
  console.log('Live certificate SPKI hash:', liveSpkiHash);

  const tlsMatch = liveSpkiHash === attestation.tls_cert_fingerprint;
  console.log('Live SPKI matches attested fingerprint:', tlsMatch);
  if (!tlsMatch) {
    console.log('  attested:', attestation.tls_cert_fingerprint);
    console.log('  live:    ', liveSpkiHash);
  }

  // 6. GPU attestation
  console.log('\n🔐 GPU attestation');
  await checkGpu(attestation, requestNonce);

  // 7. RTMR verification
  console.log('\n🔐 RTMR verification');
  checkRtmrs(attestation, intelResult);

  // 8. Compose and Sigstore
  showCompose(attestation);
  await showSigstoreProvenance(attestation);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  const urlIndex = args.indexOf('--url');
  const url = urlIndex !== -1 && args[urlIndex + 1] ? args[urlIndex + 1] : null;

  const algoIndex = args.indexOf('--signing-algo');
  const signingAlgo = algoIndex !== -1 && args[algoIndex + 1] ? args[algoIndex + 1] : 'ecdsa';

  const tokenIndex = args.indexOf('--token');
  const token = tokenIndex !== -1 && args[tokenIndex + 1] ? args[tokenIndex + 1] : (process.env.API_KEY || undefined);

  if (!url) {
    console.error('Usage: pnpm run tls -- --url https://proxy.example.com[:port] [--signing-algo ecdsa|ed25519] [--token TOKEN]');
    process.exit(1);
  }

  console.log('========================================');
  console.log('🔐 TLS Attestation Verification');
  console.log('========================================');
  console.log(`Target: ${url}`);
  console.log(`Signing algorithm: ${signingAlgo}`);

  await verifyTlsAttestation(url, signingAlgo, token);
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error.message || error);
    process.exit(1);
  });
}
