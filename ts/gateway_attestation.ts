#!/usr/bin/env node
/**
 * Verify a NEAR AI Cloud Gateway attestation.
 *
 * The peer certificate is observed while the Gateway attestation is fetched.
 * A later TLS connection could reach a different backend, so this script does
 * not compare an unrelated follow-up connection or a tls_certificate copy.
 */

import * as crypto from 'crypto';

import { fetchGatewayAttestation } from './utils/api';
import { verifyGatewayAttestation } from './utils/verifier';
import { normalizeSigningAlgo } from './utils/attestation';

function cloudApiBaseUrl(): string {
  return process.env.BASE_URL || 'https://cloud-api.near.ai';
}

async function main(): Promise<void> {
  if (!process.env.API_KEY) {
    throw new Error('API_KEY is required to fetch Cloud API Gateway evidence');
  }

  const args = process.argv.slice(2);
  const signingAlgoIndex = args.indexOf('--signing-algo');
  const signingAlgo =
    signingAlgoIndex !== -1 && args[signingAlgoIndex + 1]
      ? normalizeSigningAlgo(args[signingAlgoIndex + 1]!)
      : undefined;

  console.log('========================================');
  console.log('🔐 NEAR AI Cloud Gateway attestation');
  console.log('========================================');
  console.log('Gateway endpoint:', cloudApiBaseUrl());

  const nonce = crypto.randomBytes(32).toString('hex');
  const evidence = await fetchGatewayAttestation({ nonce, signingAlgo });
  await verifyGatewayAttestation({
    attestation: evidence.attestation,
    nonce,
    peerSpkiFingerprint: evidence.peerSpkiFingerprint,
  });
}

if (require.main === module) {
  main().catch((error) => {
    console.error(
      '\nVerification failed:',
      error instanceof Error ? error.message : error,
    );
    process.exitCode = 1;
  });
}
