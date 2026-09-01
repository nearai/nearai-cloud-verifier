import * as assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  verifyAttestationNonce,
  verifyNvidiaEvidence,
  type AttestationReport,
} from './dstack_attestation';

const nonce = 'ab'.repeat(32);
function attestation(): AttestationReport {
  return {
    intel_quote: 'aa',
    signing_address: `0x${'11'.repeat(20)}`,
    signing_algo: 'ecdsa',
    request_nonce: nonce,
    info: { tcb_info: { app_compose: '{}' } },
  };
}

test('throws when the attestation response does not echo the requested nonce', () => {
  assert.throws(
    () =>
      verifyAttestationNonce(
        { ...attestation(), request_nonce: 'cd'.repeat(32) },
        nonce,
      ),
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
        verifyNvidiaEvidence({
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
