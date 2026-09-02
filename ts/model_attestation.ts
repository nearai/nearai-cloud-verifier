#!/usr/bin/env node
/**
 * Verify NEAR AI Cloud model attestations.
 *
 * This command has no completion signature or response bytes. It verifies
 * fresh model-deployment evidence, but does not associate a model deployment
 * with a particular chat response.
 */

import * as crypto from 'crypto';

import { fetchModelAttestations } from './utils/api';
import { verifyModelAttestation } from './utils/verifier';
import { normalizeSigningAlgo } from './utils/attestation';

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
  console.log('NEAR AI Cloud model attestation');
  console.log('========================================');

  const nonce = crypto.randomBytes(32).toString('hex');
  const attestations = await fetchModelAttestations({ model, nonce, signingAlgo });
  for (const [index, attestation] of attestations.entries()) {
    console.log(
      `\n========================================\nModel attestation ${index + 1}\n========================================`,
    );
    await verifyModelAttestation({ attestation, nonce });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
