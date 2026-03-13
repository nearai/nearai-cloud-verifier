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
import * as https from 'https';
import * as tls from 'tls';
import { Buffer } from 'buffer';

import {
  checkTdxQuote,
  checkGpu,
  showCompose,
  showSigstoreProvenance,
  AttestationBaseInfo,
  IntelResult,
} from './model_verifier';

interface TlsAttestationReport extends AttestationBaseInfo {
  model_name?: string;
  tls_cert_fingerprint?: string;
  signing_public_key?: string;
  request_nonce?: string;
}

/** Cloud-api returns { gateway_attestation, model_attestations?, tls_certificate? }; fingerprint is inside gateway_attestation. */
interface AttestationReportResponse {
  gateway_attestation: TlsAttestationReport;
  model_attestations?: unknown[];
  tls_certificate?: string;
}

/**
 * Fetch attestation report AND extract the live TLS certificate SPKI hash
 * from the same connection.
 *
 * Using a single TLS connection guarantees both values come from the same
 * backend, avoiding mismatches caused by DNS round-robin or load-balancer
 * routing between multiple backends.
 */
function fetchAttestationAndSpki(
  hostname: string,
  port: number,
  nonce: string,
  signingAlgo: string = 'ecdsa',
  token?: string,
): Promise<{ attestation: TlsAttestationReport; liveSpkiHash: string }> {
  return new Promise((resolve, reject) => {
    const path = `/v1/attestation/report?include_tls_fingerprint=true&nonce=${nonce}&signing_algo=${signingAlgo}`;
    const headers: Record<string, string> = { 'Host': hostname };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const req = https.request({
      hostname,
      port,
      path,
      method: 'GET',
      headers,
      rejectUnauthorized: false, // Trust comes from TEE binding, not CA
      servername: hostname,
      timeout: 60000,
    }, (res) => {
      // Extract live SPKI hash from this TLS session
      const tlsSocket = res.socket as tls.TLSSocket;
      const cert = tlsSocket.getPeerX509Certificate();
      if (!cert) {
        reject(new Error('Failed to get certificate from server'));
        return;
      }
      const spkiDer = cert.publicKey.export({ type: 'spki', format: 'der' });
      const liveSpkiHash = crypto.createHash('sha256').update(spkiDer).digest('hex');

      // Read response body
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          return;
        }
        try {
          const response = JSON.parse(body) as AttestationReportResponse;
          const attestation = response?.gateway_attestation;
          if (!attestation) {
            reject(new Error('Attestation response missing gateway_attestation'));
            return;
          }
          resolve({ attestation, liveSpkiHash });
        } catch (e) {
          reject(new Error(`Failed to parse attestation response: ${body}`));
        }
      });
    });

    req.on('error', (error) => {
      reject(new Error(`TLS connection failed: ${error.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Attestation request timed out'));
    });

    req.end();
  });
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

  // 1. Generate nonce
  const requestNonce = crypto.randomBytes(32).toString('hex');
  console.log('Request nonce:', requestNonce);

  // 2. Fetch attestation report AND live SPKI hash from the same TLS connection.
  //    This avoids round-robin mismatches when multiple backends share a domain.
  console.log(`\nFetching attestation from ${hostname}:${port} (single TLS connection) ...`);
  const { attestation, liveSpkiHash } = await fetchAttestationAndSpki(
    hostname, port, requestNonce, signingAlgo, token,
  );

  if (!attestation.tls_cert_fingerprint) {
    throw new Error(
      'Attestation report does not include tls_cert_fingerprint. ' +
      'The proxy may not be configured to expose a TLS certificate fingerprint.'
    );
  }

  // Extract model name from attestation (self-reported by the proxy inside the TEE)
  if (attestation.model_name) {
    console.log('Model name:', attestation.model_name);
  } else {
    console.log('Model name: (not present in attestation)');
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

  // 5. Compare live certificate SPKI hash (from step 2) with attested fingerprint
  console.log('\n🔐 Live TLS certificate');
  console.log('Live certificate SPKI hash:', liveSpkiHash);

  const tlsMatch = liveSpkiHash === attestation.tls_cert_fingerprint;
  console.log('Live SPKI matches attested fingerprint:', tlsMatch);
  if (!tlsMatch) {
    console.log('  attested:', attestation.tls_cert_fingerprint);
    console.log('  live:    ', liveSpkiHash);
  }

  // 6. GPU attestation (optional; cloud-api gateway has no GPU)
  console.log('\n🔐 GPU attestation');
  if (attestation.nvidia_payload) {
    await checkGpu(attestation as import('./model_verifier').AttestationReport, requestNonce);
  } else {
    console.log('No nvidia_payload in attestation (gateway without GPU); skipping GPU check.');
  }

  // 7. Compose and Sigstore
  showCompose(attestation, intelResult);
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
