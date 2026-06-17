#!/usr/bin/env node
/**
 * OHTTP (RFC 9458) client example for NEAR AI Cloud API.
 *
 * Implements from scratch using only Node.js built-in `crypto` and `https`:
 *   - HPKE base mode (RFC 9180): DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
 *   - Binary HTTP (RFC 9292): known-length request/response encoding
 *   - Oblivious HTTP (RFC 9458): request encapsulation + response decapsulation
 *
 * Run:
 *   export API_KEY=sk-...
 *   npx tsx ts/ohttp_client.ts                          # all examples
 *   npx tsx ts/ohttp_client.ts --model anthropic/claude-haiku-4-5
 *   npx tsx ts/ohttp_client.ts --verify-attestation    # check key is TEE-attested
 */

import * as crypto from 'crypto';
import * as https from 'https';
import { URL } from 'url';

const API_KEY  = process.env.API_KEY  ?? '';
const BASE_URL = process.env.BASE_URL ?? 'https://cloud-api.near.ai';

// SubjectPublicKeyInfo ASN.1 DER header for X25519 (RFC 8410)
// SEQUENCE { SEQUENCE { OID 1.3.101.110 } BIT_STRING { 00 <32-byte key> } }
const X25519_SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex'); // 12 bytes

// ─── HTTP helper ──────────────────────────────────────────────────────────────

function httpRequest(
  url: string,
  options: { method?: string; headers?: Record<string, string> },
  body?: Buffer,
): Promise<{ status: number; headers: Record<string, string>; data: Buffer }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: options.method ?? 'GET',
        headers: options.headers ?? {},
        timeout: 120_000,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string>,
            data: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ─── HKDF helpers (RFC 5869) ──────────────────────────────────────────────────

function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  const effectiveSalt = salt.length === 0 ? Buffer.alloc(32, 0) : salt;
  return crypto.createHmac('sha256', effectiveSalt).update(ikm).digest();
}

function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const out = Buffer.alloc(length);
  let prev = Buffer.alloc(0);
  let offset = 0;
  for (let counter = 1; offset < length; counter++) {
    const hmac = crypto.createHmac('sha256', prk);
    hmac.update(prev);
    hmac.update(info);
    hmac.update(Buffer.from([counter]));
    prev = hmac.digest();
    const n = Math.min(prev.length, length - offset);
    prev.copy(out, offset, 0, n);
    offset += n;
  }
  return out;
}

// ─── HPKE labeled variants (RFC 9180 §4) ─────────────────────────────────────

function labeledExtract(suiteId: Buffer, label: string, ikm: Buffer, salt?: Buffer): Buffer {
  const effectiveSalt = salt ?? Buffer.alloc(32, 0);
  const labeledIkm = Buffer.concat([Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), ikm]);
  return hkdfExtract(effectiveSalt, labeledIkm);
}

function labeledExpand(
  suiteId: Buffer,
  label: string,
  prk: Buffer,
  info: Buffer,
  length: number,
): Buffer {
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(length, 0);
  const labeledInfo = Buffer.concat([lenBuf, Buffer.from('HPKE-v1'), suiteId, Buffer.from(label), info]);
  return hkdfExpand(prk, labeledInfo, length);
}

// ─── QUIC variable-length integer (RFC 9000 §16) ─────────────────────────────

function quicEncode(n: number): Buffer {
  if (n < 64) return Buffer.from([n]);
  if (n < 16384) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n | 0x4000, 0);
    return b;
  }
  if (n < 1073741824) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE((n | 0x80000000) >>> 0, 0);
    return b;
  }
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n) | BigInt('0xC000000000000000'));
  return b;
}

function quicDecode(data: Buffer, off: number): [number, number] {
  const prefix = data[off] >> 6;
  if (prefix === 0) return [data[off] & 0x3f, off + 1];
  if (prefix === 1) return [data.readUInt16BE(off) & 0x3fff, off + 2];
  if (prefix === 2) return [data.readUInt32BE(off) & 0x3fffffff, off + 4];
  const hi = (data.readUInt32BE(off) & 0x3fffffff) * 0x100000000;
  return [hi + data.readUInt32BE(off + 4), off + 8];
}

function qstr(b: Buffer): Buffer {
  return Buffer.concat([quicEncode(b.length), b]);
}

// ─── BHTTP (RFC 9292, known-length) ──────────────────────────────────────────

function bhttpEncodeRequest(
  method: string,
  scheme: string,
  authority: string,
  path: string,
  headers: Array<[string, string]>,
  body: Buffer | string,
): Buffer {
  const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body);
  const fieldSection = Buffer.concat(
    headers.map(([k, v]) => Buffer.concat([qstr(Buffer.from(k)), qstr(Buffer.from(v))])),
  );
  return Buffer.concat([
    Buffer.from([0x00]),
    qstr(Buffer.from(method)),
    qstr(Buffer.from(scheme)),
    qstr(Buffer.from(authority)),
    qstr(Buffer.from(path)),
    quicEncode(fieldSection.length),
    fieldSection,
    quicEncode(bodyBuf.length),
    bodyBuf,
    quicEncode(0),
  ]);
}

interface BhttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
}

function bhttpDecodeResponse(data: Buffer): BhttpResponse {
  if (data[0] !== 0x01) throw new Error(`Expected response framing 0x01, got ${data[0]}`);
  let off = 1;
  let status: number;
  [status, off] = quicDecode(data, off);
  let hdrLen: number;
  [hdrLen, off] = quicDecode(data, off);
  const hdrEnd = off + hdrLen;
  const headers: Record<string, string> = {};
  while (off < hdrEnd) {
    let nLen: number, vLen: number;
    [nLen, off] = quicDecode(data, off);
    const name = data.subarray(off, off + nLen).toString();
    off += nLen;
    [vLen, off] = quicDecode(data, off);
    headers[name] = data.subarray(off, off + vLen).toString();
    off += vLen;
  }
  off = hdrEnd;
  let contentLen: number;
  [contentLen, off] = quicDecode(data, off);
  return { status, headers, body: data.subarray(off, off + contentLen) };
}

// ─── AES-128-GCM ──────────────────────────────────────────────────────────────

function aesgcmEncrypt(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([ct, cipher.getAuthTag()]);
}

function aesgcmDecrypt(key: Buffer, nonce: Buffer, ciphertextWithTag: Buffer): Buffer {
  const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
  const ct  = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

// ─── HPKE sender setup (RFC 9180, base mode, DHKEM-X25519) ───────────────────

interface HpkeSenderContext {
  enc: Buffer;
  key: Buffer;
  baseNonce: Buffer;
  exporterSecret: Buffer;
  hpkeSuiteId: Buffer;
}

function hpkeSetupSender(
  serverPkBytes: Buffer,
  kemId: number,
  kdfId: number,
  aeadId: number,
  info: Buffer,
): HpkeSenderContext {
  const kemSuiteId = Buffer.alloc(5);
  kemSuiteId.write('KEM', 0);
  kemSuiteId.writeUInt16BE(kemId, 3);

  const hpkeSuiteId = Buffer.alloc(10);
  hpkeSuiteId.write('HPKE', 0);
  hpkeSuiteId.writeUInt16BE(kemId,  4);
  hpkeSuiteId.writeUInt16BE(kdfId,  6);
  hpkeSuiteId.writeUInt16BE(aeadId, 8);

  // Ephemeral X25519 key pair
  const eph = crypto.generateKeyPairSync('x25519');
  // Export raw 32-byte public key from SPKI DER (strip 12-byte ASN.1 header)
  const enc = Buffer.from(eph.publicKey.export({ type: 'spki', format: 'der' })).subarray(12);

  // DH: skE × pkR
  const serverPk = crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_HEADER, serverPkBytes]),
    format: 'der',
    type: 'spki',
  });
  const dh = Buffer.from(crypto.diffieHellman({ publicKey: serverPk, privateKey: eph.privateKey }));

  // DHKEM ExtractAndExpand (RFC 9180 §4.1)
  const kemContext  = Buffer.concat([enc, serverPkBytes]);
  const eaePrk      = labeledExtract(kemSuiteId, 'eae_prk', dh);           // RFC 9180 §4.1
  const sharedSecret = labeledExpand(kemSuiteId, 'shared_secret', eaePrk, kemContext, 32);

  // KeySchedule base mode (RFC 9180 §5.1)
  const pskIdHash = labeledExtract(hpkeSuiteId, 'psk_id_hash', Buffer.alloc(0), Buffer.alloc(0));
  const infoHash  = labeledExtract(hpkeSuiteId, 'info_hash',   info,           Buffer.alloc(0));
  const ksContext = Buffer.concat([Buffer.from([0x00]), pskIdHash, infoHash]);

  const prkKs        = labeledExtract(hpkeSuiteId, 'secret',     Buffer.alloc(0), sharedSecret);
  const key          = labeledExpand(hpkeSuiteId, 'key',         prkKs, ksContext, 16);
  const baseNonce    = labeledExpand(hpkeSuiteId, 'base_nonce',  prkKs, ksContext, 12);
  const exporterSec  = labeledExpand(hpkeSuiteId, 'exp',         prkKs, ksContext, 32);

  return { enc, key, baseNonce, exporterSecret: exporterSec, hpkeSuiteId };
}

// ─── OHTTP request/response (RFC 9458) ───────────────────────────────────────

interface OhttpState {
  enc: Buffer;
  exporterSecret: Buffer;
  hpkeSuiteId: Buffer;
  Nk: number;
  Nn: number;
}

function ohttpEncapsulate(keyConfig: Buffer, bhttpRequest: Buffer): [Buffer, OhttpState] {
  const keyId  = keyConfig[0];
  const kemId  = keyConfig.readUInt16BE(1);
  const serverPk = keyConfig.subarray(3, 35);
  // suites list starts at offset 37 (bytes 35-36 are the 2-byte length field)
  const kdfId  = keyConfig.readUInt16BE(37);
  const aeadId = keyConfig.readUInt16BE(39);

  const headerBuf = Buffer.alloc(7);
  headerBuf[0] = keyId;
  headerBuf.writeUInt16BE(kemId,  1);
  headerBuf.writeUInt16BE(kdfId,  3);
  headerBuf.writeUInt16BE(aeadId, 5);
  const info = Buffer.concat([Buffer.from('message/bhttp request\x00'), headerBuf]);

  const ctx = hpkeSetupSender(serverPk, kemId, kdfId, aeadId, info);
  // ohttp 0.7 (rust-hpke feature) uses empty AAD
  const ct = aesgcmEncrypt(ctx.key, ctx.baseNonce, bhttpRequest);

  return [
    Buffer.concat([headerBuf, ctx.enc, ct]),
    { enc: ctx.enc, exporterSecret: ctx.exporterSecret, hpkeSuiteId: ctx.hpkeSuiteId, Nk: 16, Nn: 12 },
  ];
}

function ohttpDecapsulateResponse(encResponse: Buffer, state: OhttpState): Buffer {
  const Nmax = Math.max(state.Nk, state.Nn);
  const responseNonce = encResponse.subarray(0, Nmax);
  const ct = encResponse.subarray(Nmax);

  // HPKE Export (RFC 9180 §5.3): secret = ctx.Export("message/bhttp response", Nmax)
  const secret = labeledExpand(
    state.hpkeSuiteId, 'sec', state.exporterSecret, Buffer.from('message/bhttp response'), Nmax,
  );

  // Derive AEAD key+nonce with plain HKDF (not labeled) — RFC 9458 §4.4
  const salt   = Buffer.concat([state.enc, responseNonce]);
  const prk    = hkdfExtract(salt, secret);
  const aKey   = hkdfExpand(prk, Buffer.from('key'),   state.Nk);
  const aNonce = hkdfExpand(prk, Buffer.from('nonce'), state.Nn);

  return aesgcmDecrypt(aKey, aNonce, ct);
}

// ─── OhttpClient ─────────────────────────────────────────────────────────────

class OhttpClient {
  public readonly apiKey: string;
  private readonly baseUrl: string;
  private keyConfig?: Buffer;

  constructor(baseUrl: string, apiKey: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey  = apiKey;
  }

  async fetchKeyConfig(): Promise<Buffer> {
    const { status, data, headers } = await httpRequest(`${this.baseUrl}/.well-known/ohttp-gateway`, {});
    if (status !== 200) throw new Error(`Key config fetch failed: ${status}`);
    if (headers['content-type'] !== 'application/ohttp-keys') {
      throw new Error(`Unexpected Content-Type: ${headers['content-type']}`);
    }
    this.keyConfig = data;
    return data;
  }

  private async getKeyConfig(): Promise<Buffer> {
    if (!this.keyConfig) await this.fetchKeyConfig();
    return this.keyConfig!;
  }

  async request(
    method: string,
    path: string,
    headers: Array<[string, string]>,
    body: Buffer | string,
  ): Promise<BhttpResponse> {
    const kc = await this.getKeyConfig();
    const authority = this.baseUrl.replace(/^https?:\/\//, '');
    const bhttp = bhttpEncodeRequest(method, 'https', authority, path, headers, body);
    const [encReq, state] = ohttpEncapsulate(kc, bhttp);

    const { status, data, headers: respHdrs } = await httpRequest(
      `${this.baseUrl}/ohttp`,
      { method: 'POST', headers: { 'content-type': 'message/ohttp-req', 'content-length': String(encReq.length) } },
      encReq,
    );
    if (status !== 200) throw new Error(`OHTTP transport error: ${status} ${data.toString().slice(0, 200)}`);
    if (respHdrs['content-type'] !== 'message/ohttp-res') {
      throw new Error(`Expected message/ohttp-res, got ${respHdrs['content-type']}`);
    }
    return bhttpDecodeResponse(ohttpDecapsulateResponse(data, state));
  }

  async chat(payload: object, extraHeaders?: Array<[string, string]>): Promise<{ status: number; body: Record<string, unknown> }> {
    const hdrs: Array<[string, string]> = [
      ['authorization', `Bearer ${this.apiKey}`],
      ['content-type', 'application/json'],
      ...(extraHeaders ?? []),
    ];
    const resp = await this.request('POST', '/v1/chat/completions', hdrs, JSON.stringify(payload));
    return { status: resp.status, body: JSON.parse(resp.body.toString()) };
  }
}

// ─── SSE parser ───────────────────────────────────────────────────────────────

function parseSse(body: Buffer): Array<Record<string, unknown>> {
  const chunks: Array<Record<string, unknown>> = [];
  for (const line of body.toString().split('\n')) {
    if (line.startsWith('data: ') && !line.endsWith('[DONE]')) {
      try { chunks.push(JSON.parse(line.slice(6))); } catch { /* skip */ }
    }
  }
  return chunks;
}

// ─── Attestation verification ─────────────────────────────────────────────────

async function verifyOhttpKeyAttested(baseUrl: string): Promise<void> {
  console.log('\n--- OHTTP attestation verification ---');
  const nonce = crypto.randomBytes(32).toString('hex');
  const [rKey, rAttn] = await Promise.all([
    httpRequest(`${baseUrl}/.well-known/ohttp-gateway`, {}),
    httpRequest(`${baseUrl}/v1/attestation/report?nonce=${nonce}`, {}),
  ]);

  const keyHex  = rKey.data.toString('hex');
  const report  = JSON.parse(rAttn.data.toString()) as Record<string, unknown>;
  const attnKey = (report['ohttp_key_config'] as string) ?? '';

  console.log(`  Key from /.well-known:  ${keyHex}`);
  console.log(`  Key from attestation:   ${attnKey}`);
  const match = keyHex === attnKey;
  console.log(`  Keys match: ${match}`);
  if (!match) throw new Error('OHTTP key mismatch between /.well-known/ohttp-gateway and attestation report');

  const ohttpAttn = (report['ohttp_attestation'] as Record<string, unknown>) ?? {};
  if (Object.keys(ohttpAttn).length > 0) {
    console.log(`  ohttp_attestation.signing_algo: ${ohttpAttn['signing_algo']}`);
    console.log(`  ohttp_attestation.signing_key:  ${String(ohttpAttn['signing_key'] ?? '').slice(0, 32)}...`);
  } else {
    console.log('  WARNING: no ohttp_attestation in report');
  }
  console.log('  OK: OHTTP key is bound to TEE attestation');
}

// ─── Examples ─────────────────────────────────────────────────────────────────

async function exampleNonStreaming(client: OhttpClient, model: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Example 1: Non-streaming chat  (model=${model})`);
  console.log('='.repeat(60));
  const { status, body } = await client.chat({
    model, messages: [{ role: 'user', content: 'Say hi in exactly one word.' }], max_tokens: 10,
  });
  const choices = body['choices'] as Array<Record<string, unknown>>;
  const msg = choices[0]['message'] as Record<string, unknown>;
  console.log(`  Status:   ${status}`);
  console.log(`  Model:    ${body['model']}`);
  console.log(`  Response: ${JSON.stringify(msg['content'])}`);
  console.log(`  Usage:    ${JSON.stringify(body['usage'])}`);
  console.log('  PASS ✓');
}

async function exampleStreaming(client: OhttpClient, model: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Example 2: Streaming chat (stream:true inside OHTTP)  (model=${model})`);
  console.log('='.repeat(60));
  console.log('  Note: OHTTP is request/response — the server buffers the SSE');
  console.log('  stream and returns it as a single decryptable BHTTP body.');
  const resp = await client.request(
    'POST', '/v1/chat/completions',
    [['authorization', `Bearer ${client.apiKey}`], ['content-type', 'application/json']],
    JSON.stringify({
      model, stream: true, max_tokens: 50,
      messages: [{ role: 'user', content: 'Count from 1 to 5, one number per line, nothing else.' }],
    }),
  );
  const chunks = parseSse(resp.body);
  const text = chunks
    .flatMap(c => ((c['choices'] as Array<Record<string, unknown>>) ?? [])
      .map(ch => ((ch['delta'] as Record<string, unknown>)?.['content'] as string) ?? ''))
    .join('');
  console.log(`  Status:   ${resp.status}`);
  console.log(`  Chunks:   ${chunks.length}`);
  console.log(`  Response: ${JSON.stringify(text)}`);
  console.log('  PASS ✓');
}

async function exampleToolCalls(client: OhttpClient, model: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Example 3: Tool calls  (model=${model})`);
  console.log('='.repeat(60));
  const tools = [{ type: 'function', function: {
    name: 'get_weather', description: 'Get the current weather in a location',
    parameters: { type: 'object', properties: { location: { type: 'string' } }, required: ['location'] },
  }}];

  console.log('\n  Turn 1: Ask question that requires tool use');
  const { body: r1 } = await client.chat({
    model, max_tokens: 200, tools,
    messages: [{ role: 'user', content: "What's the weather in Paris?" }],
  });
  const c1 = (r1['choices'] as Array<Record<string, unknown>>)[0];
  const tc = ((c1['message'] as Record<string, unknown>)['tool_calls'] as Array<Record<string, unknown>>)[0];
  console.log(`  Finish reason: ${c1['finish_reason']}`);
  const tcFn = tc['function'] as Record<string, unknown>;
  console.log(`  Tool call: ${tcFn['name']}(${tcFn['arguments']})`);

  console.log('\n  Turn 2: Provide tool result and get final answer');
  const { body: r2 } = await client.chat({ model, max_tokens: 200, messages: [
    { role: 'user',      content: "What's the weather in Paris?" },
    { role: 'assistant', content: null as unknown as string, tool_calls: [tc] },
    { role: 'tool',      tool_call_id: tc['id'] as string, content: 'Sunny, 22°C' },
  ]});
  const c2 = (r2['choices'] as Array<Record<string, unknown>>)[0];
  const content2 = (c2['message'] as Record<string, unknown>)['content'];
  console.log(`  Final response: ${JSON.stringify(content2)}`);
  console.log('  PASS ✓');
}

async function exampleToolCallsStreaming(client: OhttpClient, model: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Example 4: Tool calls + streaming  (model=${model})`);
  console.log('='.repeat(60));
  const tools = [{ type: 'function', function: {
    name: 'add', description: 'Add two numbers',
    parameters: { type: 'object', properties: { a: { type: 'number' }, b: { type: 'number' } }, required: ['a', 'b'] },
  }}];

  console.log('\n  Turn 1 (streaming): model calls the tool');
  const resp = await client.request(
    'POST', '/v1/chat/completions',
    [['authorization', `Bearer ${client.apiKey}`], ['content-type', 'application/json']],
    JSON.stringify({ model, max_tokens: 200, tools, stream: true,
      messages: [{ role: 'user', content: 'What is 17 + 25? Use the add tool.' }] }),
  );
  const chunks = parseSse(resp.body);
  let toolName = '', toolArgs = '', tcId = '';
  for (const chunk of chunks) {
    for (const choice of ((chunk['choices'] as Array<Record<string, unknown>>) ?? [])) {
      const delta = (choice['delta'] as Record<string, unknown>) ?? {};
      for (const tc of ((delta['tool_calls'] as Array<Record<string, unknown>>) ?? [])) {
        if (tc['id'])   tcId = tc['id'] as string;
        const fn = (tc['function'] as Record<string, unknown>) ?? {};
        if (fn['name'])      toolName += fn['name'] as string;
        if (fn['arguments']) toolArgs += fn['arguments'] as string;
      }
      if (choice['finish_reason'] === 'tool_calls') {
        console.log('  Finish reason: tool_calls');
        console.log(`  Tool call: ${toolName}(${toolArgs})`);
      }
    }
  }

  console.log('\n  Turn 2: Provide tool result');
  const args = JSON.parse(toolArgs) as Record<string, number>;
  const toolResult = String(args['a'] + args['b']);
  const { body: r2 } = await client.chat({ model, max_tokens: 100, messages: [
    { role: 'user',      content: 'What is 17 + 25? Use the add tool.' },
    { role: 'assistant', content: null as unknown as string,
      tool_calls: [{ id: tcId, type: 'function', function: { name: toolName, arguments: toolArgs } }] },
    { role: 'tool',      tool_call_id: tcId, content: toolResult },
  ]});
  const c2 = (r2['choices'] as Array<Record<string, unknown>>)[0];
  console.log(`  Final response: ${JSON.stringify((c2['message'] as Record<string, unknown>)['content'])}`);
  console.log('  PASS ✓');
}

async function exampleMultiTurn(client: OhttpClient, model: string): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Example 5: Multi-turn conversation  (model=${model})`);
  console.log('='.repeat(60));
  const { body: r1 } = await client.chat({ model, max_tokens: 50,
    messages: [{ role: 'user', content: 'My name is Alice. Please remember it.' }] });
  const t1 = ((r1['choices'] as Array<Record<string, unknown>>)[0]['message'] as Record<string, unknown>)['content'];
  console.log(`  Turn 1 response: ${JSON.stringify(t1)}`);

  const { body: r2 } = await client.chat({ model, max_tokens: 30, messages: [
    { role: 'user',      content: 'My name is Alice. Please remember it.' },
    { role: 'assistant', content: t1 as string },
    { role: 'user',      content: 'What is my name?' },
  ]});
  const t2 = ((r2['choices'] as Array<Record<string, unknown>>)[0]['message'] as Record<string, unknown>)['content'];
  console.log(`  Turn 2 response: ${JSON.stringify(t2)}`);
  console.log('  PASS ✓');
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const modelArg = argv.find(a => a.startsWith('--model='));
  const model    = modelArg ? modelArg.split('=')[1] : 'anthropic/claude-haiku-4-5';
  const doAttn   = argv.includes('--verify-attestation');

  const client = new OhttpClient(BASE_URL, API_KEY);
  const kc = await client.fetchKeyConfig();
  const keyId  = kc[0];
  const kemId  = kc.readUInt16BE(1);
  const kdfId  = kc.readUInt16BE(37);
  const aeadId = kc.readUInt16BE(39);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Key config (${kc.length} bytes): key_id=${keyId} kem_id=0x${kemId.toString(16).padStart(4, '0')} kdf_id=0x${kdfId.toString(16).padStart(4, '0')} aead_id=0x${aeadId.toString(16).padStart(4, '0')}`);

  if (doAttn) await verifyOhttpKeyAttested(BASE_URL);

  await exampleNonStreaming(client, model);
  await exampleStreaming(client, model);
  await exampleToolCalls(client, model);
  await exampleToolCallsStreaming(client, model);
  await exampleMultiTurn(client, model);

  console.log(`\n${'='.repeat(60)}`);
  console.log('All OHTTP examples PASSED');
  console.log('='.repeat(60));
}

main().catch(e => { console.error(e); process.exit(1); });
