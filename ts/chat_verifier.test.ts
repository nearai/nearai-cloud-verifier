import * as assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import * as http from 'node:http';
import { test } from 'node:test';
import { ethers } from 'ethers';

import {
  type CompletionSignature,
  fetchGatewayAttestationForSignature,
  fetchModelAttestationForSignature,
  parseSignaturePayload,
  signatureTextFor,
  verifyGatewayResponse,
  verifyModelResponse,
} from './chat_verifier';
import { type AttestationReport, fetchModelAttestations } from './model_verifier';

const nonce = 'ab'.repeat(32);
const modelSigningAddress = `0x${'11'.repeat(20)}`;
const ed25519SigningAddress = '22'.repeat(32);

type RequestCapture = {
  authorization?: string;
  noAliasing?: string;
  url?: URL;
};

function hash(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function providerSignature(): CompletionSignature {
  return {
    kind: 'provider_tee',
    signedText: 'canonical-model:request:response',
    signature: '00',
    signingAddress: modelSigningAddress,
    signingAlgo: 'ecdsa',
  };
}

function gatewaySignature(): CompletionSignature {
  return {
    kind: 'gateway',
    signedText: 'request:response',
    signature: '00',
    signingAddress: ed25519SigningAddress,
    signingAlgo: 'ed25519',
  };
}

function attestation(
  requestNonce: string,
  signingAddress: string,
  signingAlgo: string,
): Record<string, unknown> {
  return {
    intel_quote: 'aa',
    signing_address: signingAddress,
    signing_algo: signingAlgo,
    request_nonce: requestNonce,
    event_log: [],
    info: { tcb_info: { app_compose: '{}' } },
  };
}

async function withCloudApi(
  bodyForRequest: (url: URL) => unknown,
  run: (capture: RequestCapture) => Promise<void>,
): Promise<void> {
  const capture: RequestCapture = {};
  const server = http.createServer((request, response) => {
    capture.authorization = request.headers.authorization;
    capture.noAliasing = request.headers['x-no-aliasing'] as string | undefined;
    capture.url = new URL(request.url ?? '/', `http://${request.headers.host}`);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify(bodyForRequest(capture.url)));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const previousBaseUrl = process.env.BASE_URL;
  const previousApiKey = process.env.API_KEY;
  process.env.BASE_URL = `http://127.0.0.1:${address.port}`;
  process.env.API_KEY = 'test-api-key';

  try {
    await run(capture);
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.BASE_URL;
    } else {
      process.env.BASE_URL = previousBaseUrl;
    }
    if (previousApiKey === undefined) {
      delete process.env.API_KEY;
    } else {
      process.env.API_KEY = previousApiKey;
    }
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}

test('requires signature_kind instead of inferring provenance from signed text', () => {
  const found = {
    text: 'canonical-model:request-hash:response-hash',
    signature: '00',
    signing_address: modelSigningAddress,
    signing_algo: 'ecdsa',
  };

  assert.throws(() => parseSignaturePayload(found), /signature_kind/);
  assert.throws(
    () => parseSignaturePayload({ ...found, signature_kind: 'other' }),
    /Unsupported signature_kind/,
  );
  assert.equal(
    parseSignaturePayload({ ...found, signature_kind: 'provider_tee' }).kind,
    'provider_tee',
  );
});

test('builds signature text from the exact request and response bytes', () => {
  const requestBody = Buffer.from('{"model":"canonical-model", "stream":true}');
  const responseBody = Buffer.from('data: {"id":"chat-1"}\n\n');
  const reserializedResponse = Buffer.from(
    JSON.stringify({ id: 'chat-1' }),
  );

  assert.equal(
    signatureTextFor({
      kind: 'provider_tee',
      model: 'canonical-model',
      requestBody,
      responseBody,
    }),
    `canonical-model:${hash(requestBody)}:${hash(responseBody)}`,
  );
  assert.equal(
    signatureTextFor({ kind: 'gateway', requestBody, responseBody }),
    `${hash(requestBody)}:${hash(responseBody)}`,
  );
  assert.notEqual(
    signatureTextFor({
      kind: 'gateway',
      requestBody,
      responseBody: reserializedResponse,
    }),
    signatureTextFor({ kind: 'gateway', requestBody, responseBody }),
  );
});

test('verifies an ECDSA provider_tee signature against matching model evidence', async () => {
  const wallet = ethers.Wallet.createRandom();
  const requestBody = Buffer.from('{"model":"canonical-model"}');
  const responseBody = Buffer.from('{"id":"chat-1"}');
  const signedText = signatureTextFor({
    kind: 'provider_tee',
    requestBody,
    responseBody,
    model: 'canonical-model',
  });
  const signature: CompletionSignature = {
    kind: 'provider_tee',
    signedText,
    signature: await wallet.signMessage(signedText),
    signingAddress: wallet.address,
    signingAlgo: 'ecdsa',
  };
  const evidence = attestation(nonce, wallet.address, 'ecdsa') as AttestationReport;

  assert.doesNotThrow(() =>
    verifyModelResponse({ requestBody, responseBody, signature, attestation: evidence }),
  );
  assert.throws(
    () =>
      verifyModelResponse({
        requestBody,
        responseBody: Buffer.from('{"id":"different"}'),
        signature,
        attestation: evidence,
      }),
    /Signature text does not match/,
  );
});

test('verifies an Ed25519 gateway signature against matching Gateway evidence', () => {
  const keys = generateKeyPairSync('ed25519');
  const publicKeyDer = keys.publicKey.export({ type: 'spki', format: 'der' });
  const signingAddress = Buffer.from(publicKeyDer).subarray(-32).toString('hex');
  const requestBody = Buffer.from('{"model":"canonical-model"}');
  const responseBody = Buffer.from('{"id":"chat-1"}');
  const signedText = signatureTextFor({
    kind: 'gateway',
    requestBody,
    responseBody,
  });
  const signature: CompletionSignature = {
    kind: 'gateway',
    signedText,
    signature: sign(null, Buffer.from(signedText), keys.privateKey).toString('hex'),
    signingAddress,
    signingAlgo: 'ed25519',
  };
  const evidence = attestation(nonce, signingAddress, 'ed25519') as AttestationReport;

  assert.doesNotThrow(() =>
    verifyGatewayResponse({ requestBody, responseBody, signature, attestation: evidence }),
  );
  assert.throws(
    () =>
      verifyGatewayResponse({
        requestBody,
        responseBody,
        signature,
        attestation: {
          ...evidence,
          signing_address: '33'.repeat(32),
        },
      }),
    /Signature signer does not match/,
  );
});

test('fetches NEAR model evidence only for a provider_tee signature', async () => {
  await withCloudApi(
    (url) => ({
      model_attestations: [
        attestation(
          url.searchParams.get('nonce') ?? '',
          modelSigningAddress,
          'ecdsa',
        ),
      ],
    }),
    async (capture) => {
      const evidence = await fetchModelAttestationForSignature({
        model: 'canonical-model',
        nonce,
        signature: providerSignature(),
      });

      assert.equal(evidence.signing_address, modelSigningAddress);
      assert.equal(capture.authorization, 'Bearer test-api-key');
      assert.equal(capture.noAliasing, 'true');
      assert.equal(capture.url?.pathname, '/v1/attestation/report');
      assert.equal(capture.url?.searchParams.get('model'), 'canonical-model');
      assert.equal(capture.url?.searchParams.get('provider'), 'near');
      assert.equal(capture.url?.searchParams.get('nonce'), nonce);
      assert.equal(capture.url?.searchParams.get('signing_algo'), 'ecdsa');
      assert.equal(
        capture.url?.searchParams.get('signing_address'),
        modelSigningAddress,
      );
      assert.equal(
        capture.url?.searchParams.get('include_tls_fingerprint'),
        'false',
      );
    },
  );
});

test('fetches an array of NEAR model evidence for a deployment audit', async () => {
  await withCloudApi(
    (url) => ({
      model_attestations: [
        attestation(
          url.searchParams.get('nonce') ?? '',
          ed25519SigningAddress,
          'ed25519',
        ),
      ],
    }),
    async (capture) => {
      const evidence = await fetchModelAttestations({
        model: 'canonical-model',
        nonce,
        signingAlgo: 'ed25519',
      });

      assert.equal(evidence.length, 1);
      assert.equal(evidence[0]?.signing_address, ed25519SigningAddress);
      assert.equal(capture.authorization, 'Bearer test-api-key');
      assert.equal(capture.noAliasing, 'true');
      assert.equal(capture.url?.searchParams.get('model'), 'canonical-model');
      assert.equal(capture.url?.searchParams.get('provider'), 'near');
      assert.equal(capture.url?.searchParams.get('nonce'), nonce);
      assert.equal(capture.url?.searchParams.get('signing_algo'), 'ed25519');
      assert.equal(
        capture.url?.searchParams.get('include_tls_fingerprint'),
        'false',
      );
      assert.equal(capture.url?.searchParams.has('signing_address'), false);
    },
  );
});

test('fetches Gateway evidence only for a gateway signature', async () => {
  await withCloudApi(
    (url) => ({
      gateway_attestation: attestation(
        url.searchParams.get('nonce') ?? '',
        ed25519SigningAddress,
        'ed25519',
      ),
    }),
    async (capture) => {
      const evidence = await fetchGatewayAttestationForSignature({
        nonce,
        signature: gatewaySignature(),
      });

      assert.equal(evidence.attestation.signing_address, ed25519SigningAddress);
      assert.equal(capture.authorization, 'Bearer test-api-key');
      assert.equal(capture.noAliasing, undefined);
      assert.equal(capture.url?.pathname, '/v1/attestation/report');
      assert.equal(capture.url?.searchParams.get('nonce'), nonce);
      assert.equal(capture.url?.searchParams.get('signing_algo'), 'ed25519');
      assert.equal(
        capture.url?.searchParams.get('include_tls_fingerprint'),
        'true',
      );
      assert.equal(capture.url?.searchParams.has('model'), false);
      assert.equal(capture.url?.searchParams.has('provider'), false);
      assert.equal(capture.url?.searchParams.has('signing_address'), false);
    },
  );
});
