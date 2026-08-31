import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  checkGpu,
  checkReportData,
  type AttestationReport,
  type IntelResult,
} from './model_verifier';

const nonce = 'ab'.repeat(32);
const signingAddress = `0x${'11'.repeat(20)}`;

function reportData(): string {
  return Buffer.concat([
    Buffer.from(signingAddress.slice(2), 'hex'),
    Buffer.alloc(12),
    Buffer.from(nonce, 'hex'),
  ]).toString('hex');
}

function attestation(): AttestationReport {
  return {
    intel_quote: 'aa',
    signing_address: signingAddress,
    signing_algo: 'ecdsa',
    request_nonce: nonce,
    info: { tcb_info: { app_compose: '{}' } },
  };
}

function verifiedQuote(): IntelResult {
  return {
    quote: {
      body: {
        reportdata: reportData(),
        mrconfig: '',
        rtmr3: '',
        tdattributes: '00',
      },
      verified: true,
      status: 'UpToDate',
      advisory_ids: [],
      debug_enabled: false,
    },
  };
}

test('throws when the attestation response does not echo the requested nonce', () => {
  assert.throws(
    () =>
      checkReportData({
        attestation: { ...attestation(), request_nonce: 'cd'.repeat(32) },
        requestNonce: nonce,
        intelResult: verifiedQuote(),
      }),
    /request_nonce does not match/,
  );
});

test('requires the NRAS overall verdict to be tagged as a JWT', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify([['unexpected', 'not-used']]), { status: 200 });

  try {
    await assert.rejects(
      () =>
        checkGpu({
          attestation: {
            ...attestation(),
            nvidia_payload: JSON.stringify({ nonce }),
          },
          requestNonce: nonce,
        }),
      /overall verdict JWT/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});
