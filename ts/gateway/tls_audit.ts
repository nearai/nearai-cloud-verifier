#!/usr/bin/env node
/**
 * Verify the TLS identity of the configured NEAR AI Cloud Gateway.
 *
 * The peer certificate is observed while the Gateway attestation is fetched.
 * A later TLS connection could reach a different backend, so this script does
 * not compare an unrelated follow-up connection or a tls_certificate copy.
 */

import { auditGatewayAttestation } from './deployment_audit';

function cloudApiBaseUrl(): string {
  return process.env.BASE_URL || 'https://cloud-api.near.ai';
}

async function main(): Promise<void> {
  if (!process.env.API_KEY) {
    throw new Error('API_KEY is required to fetch Cloud API Gateway evidence');
  }

  console.log('========================================');
  console.log('🔐 Gateway TLS attestation');
  console.log('========================================');
  console.log('Gateway endpoint:', cloudApiBaseUrl());

  await auditGatewayAttestation();
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
