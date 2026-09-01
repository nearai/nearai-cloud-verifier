#!/usr/bin/env node
/**
 * Independently audit Cloud API Gateway and model-serving deployments.
 *
 * This command deliberately has no completion signature or response bytes.
 * It establishes that the returned attestations are fresh and valid deployment
 * evidence, but it does not associate either deployment with a chat response.
 */

import * as crypto from 'crypto';

import {
  type SigningAlgo,
  fetchGatewayAttestation,
  fetchModelAttestations,
} from './cloud_api';
import {
  type VerifiedGatewayAttestation,
  verifyGatewayAttestation,
  verifyModelAttestation,
} from './attestation';
import { normalizeSigningAlgo } from '../common/dstack_attestation';

export interface AuditModelAttestationsParams {
  model: string;
  nonce?: string;
  signingAlgo?: SigningAlgo;
}

export interface AuditGatewayAttestationParams {
  nonce?: string;
  signingAlgo?: SigningAlgo;
}

/**
 * Fetch and independently audit Gateway evidence. This verifies the Gateway
 * deployment and its evidence-request TLS peer, not a particular completion.
 */
export async function auditGatewayAttestation({
  nonce = crypto.randomBytes(32).toString('hex'),
  signingAlgo,
}: AuditGatewayAttestationParams = {}): Promise<VerifiedGatewayAttestation> {
  const evidence = await fetchGatewayAttestation({ nonce, signingAlgo });
  return verifyGatewayAttestation({
    attestation: evidence.attestation,
    nonce,
    peerSpkiFingerprint: evidence.peerSpkiFingerprint,
  });
}

/**
 * Fetch and independently audit every NEAR model attestation for a model.
 * The result is deployment evidence only; no completion is involved.
 */
export async function auditModelAttestations({
  model,
  nonce = crypto.randomBytes(32).toString('hex'),
  signingAlgo,
}: AuditModelAttestationsParams): Promise<void> {
  const attestations = await fetchModelAttestations({ model, nonce, signingAlgo });
  for (const [index, attestation] of attestations.entries()) {
    console.log(
      `\n========================================\nModel attestation ${index + 1}\n========================================`,
    );
    await verifyModelAttestation({ attestation, nonce });
  }
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
  console.log('NEAR AI Cloud Gateway deployment audit');
  console.log('========================================');

  await auditGatewayAttestation({ signingAlgo });
  await auditModelAttestations({ model, signingAlgo });
}

if (require.main === module) {
  main().catch((error) => {
    console.error('\nVerification failed:', error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
