import * as assert from 'node:assert/strict';
import * as http from 'node:http';
import { test } from 'node:test';

test('fetchAttestationFor authenticates the signing-address lookup', async () => {
  let authorizationHeader: string | undefined;
  let requestUrl: string | undefined;
  const signingAddress = '0x6520000000000000000000000000000000000000';

  const server = http.createServer((request, response) => {
    authorizationHeader = request.headers.authorization;
    requestUrl = request.url;
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({
      model_attestations: [{ signing_address: signingAddress }],
    }));
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    process.env.API_KEY = 'test-api-key';
    process.env.BASE_URL = `http://127.0.0.1:${address.port}`;

    const { fetchAttestationFor } = await import('./chat_verifier');
    const [attestation] = await fetchAttestationFor(signingAddress, 'test/model');

    assert.equal(authorizationHeader, 'Bearer test-api-key');
    assert.match(requestUrl ?? '', /^\/v1\/attestation\/report\?/);
    assert.match(requestUrl ?? '', /model=test%2Fmodel/);
    assert.match(requestUrl ?? '', new RegExp(`signing_address=${signingAddress}`));
    assert.equal(attestation.signing_address, signingAddress);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
    });
  }
});
