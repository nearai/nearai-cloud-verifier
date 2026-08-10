import * as assert from 'node:assert/strict';
import * as http from 'node:http';
import { test } from 'node:test';

test('fetchReport authenticates gateway attestation requests', async () => {
  let authorizationHeader: string | undefined;
  let requestUrl: string | undefined;

  const server = http.createServer((request, response) => {
    authorizationHeader = request.headers.authorization;
    requestUrl = request.url;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    process.env.API_KEY = 'test-api-key';
    process.env.BASE_URL = `http://127.0.0.1:${address.port}`;

    const { fetchReport } = await import('./model_verifier');
    await fetchReport(
      'test/model',
      'test-nonce',
      'ed25519',
      true,
      'test-signing-address',
    );

    assert.equal(authorizationHeader, 'Bearer test-api-key');
    assert.match(requestUrl ?? '', /^\/v1\/attestation\/report\?/);
    assert.match(requestUrl ?? '', /model=test%2Fmodel/);
    assert.match(requestUrl ?? '', /nonce=test-nonce/);
    assert.match(requestUrl ?? '', /signing_algo=ed25519/);
    assert.match(requestUrl ?? '', /include_tls_fingerprint=true/);
    assert.match(requestUrl ?? '', /signing_address=test-signing-address/);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
