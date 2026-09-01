#!/usr/bin/env node
/**
 * TLS Certificate Verification for a NEAR AI Model Endpoint
 *
 * Verifies that a model-serving endpoint's TLS connection terminates inside the TEE
 * by checking that the live TLS certificate's SPKI hash is bound into the
 * Intel TDX attestation quote.
 *
 * How it works:
 *   1. Connects to the model endpoint and fetches an attestation report with
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
 *   pnpm run model-tls -- --url https://your-model.completions.near.ai
 *   pnpm run model-tls -- --url https://your-model.completions.near.ai --signing-algo ed25519
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as tls from 'tls';
import { Buffer } from 'buffer';

import {
  hexBytesOfLength,
  verifyDstackQuote,
  verifyDstackDeployment,
  verifyNvidiaEvidence,
  verifyAttestationNonce,
  verifyReportDataBindingWithTlsFingerprint,
  type AttestationReport,
} from '../common/dstack_attestation';

/**
 * Fetch attestation report AND extract the live TLS certificate SPKI hash
 * from the same connection.
 *
 * Using a single TLS connection guarantees both values come from the same
 * backend, avoiding mismatches caused by DNS round-robin or load-balancer
 * routing between multiple backends.
 */
function fetchModelAttestationAndSpki(
  hostname: string,
  port: number,
  nonce: string,
  signingAlgo: string = 'ecdsa',
  token?: string,
): Promise<{ attestation: AttestationReport; liveSpkiHash: string }> {
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
      // The observed peer certificate must belong to the connection that
      // served this report, rather than an agent-reused socket.
      agent: false,
      timeout: 60000,
    }, (res) => {
      // Extract live SPKI hash from this TLS session
      const tlsSocket = res.socket as tls.TLSSocket;
      const cert = peerCertificate(tlsSocket);
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
          const parsed = JSON.parse(body) as unknown;
          const attestation = parsed as AttestationReport;
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

/** Fall back to the raw peer certificate when Node did not retain X509 state. */
function peerCertificate(socket: tls.TLSSocket): crypto.X509Certificate | undefined {
  const certificate = socket.getPeerX509Certificate();
  if (certificate !== undefined) {
    return certificate;
  }

  const peer = socket.getPeerCertificate(true);
  return peer.raw === undefined ? undefined : new crypto.X509Certificate(peer.raw);
}

/**
 * Main verification flow: prove that a model endpoint's TLS certificate is bound to the TEE.
 */
export async function verifyDirectModelTlsAttestation(
  url: string,
  signingAlgo: string = 'ecdsa',
  token?: string,
): Promise<void> {
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
  const { attestation, liveSpkiHash } = await fetchModelAttestationAndSpki(
    hostname, port, requestNonce, signingAlgo, token,
  );

  // Check the response's untrusted convenience echo before spending work on
  // quote verification. Freshness is still established by quote report_data.
  verifyAttestationNonce(attestation, requestNonce);

  if (!attestation.tls_cert_fingerprint) {
    throw new Error(
      'Attestation report does not include tls_cert_fingerprint. ' +
      'The model endpoint may not be configured to expose a TLS certificate fingerprint.'
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
  const intelResult = await verifyDstackQuote(attestation);

  // 4. Verify report data binds signing address + TLS fingerprint + nonce
  console.log('\n🔐 TDX report data (TLS mode)');
  verifyReportDataBindingWithTlsFingerprint({
    attestation,
    requestNonce,
    intelResult,
  });

  // 5. Compare live certificate SPKI hash (from step 2) with attested fingerprint
  console.log('\n🔐 Live TLS certificate');
  console.log('Live certificate SPKI hash:', liveSpkiHash);

  const tlsMatch = hexBytesOfLength(
    liveSpkiHash,
    32,
    'live TLS certificate SPKI fingerprint',
  ).equals(
    hexBytesOfLength(
      attestation.tls_cert_fingerprint,
      32,
      'attestation.tls_cert_fingerprint',
    ),
  );
  console.log('Live SPKI matches attested fingerprint:', tlsMatch);
  if (!tlsMatch) {
    console.log('  attested:', attestation.tls_cert_fingerprint);
    console.log('  live:    ', liveSpkiHash);
    throw new Error('Live TLS SPKI fingerprint does not match the attestation');
  }

  // 6. GPU attestation (optional; cloud-api gateway has no GPU)
  console.log('\n🔐 GPU attestation');
  if (attestation.nvidia_payload) {
    await verifyNvidiaEvidence({ attestation, requestNonce });
  } else {
    console.log('No nvidia_payload in attestation; skipping GPU check.');
  }

  // 7. Measured deployment
  await verifyDstackDeployment({ attestation, intelResult });
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
    console.error('Usage: pnpm run model-tls -- --url https://your-model.completions.near.ai[:port] [--signing-algo ecdsa|ed25519] [--token TOKEN]');
    process.exit(1);
  }

  console.log('========================================');
  console.log('🔐 Model TLS Attestation Verification');
  console.log('========================================');
  console.log(`Target: ${url}`);
  console.log(`Signing algorithm: ${signingAlgo}`);

  await verifyDirectModelTlsAttestation(url, signingAlgo, token);
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error.message || error);
    process.exit(1);
  });
}
