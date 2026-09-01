#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud End-to-End Encryption Test
 * Test end-to-end encryption for chat completions.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import * as ed2curve from 'ed2curve';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { verifyCompletion } from '../gateway/completion';
import type { SigningAlgo } from '../common/dstack_attestation';

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';
const MAX_TOKENS = 100;

function cloudApiUrl(path: string): URL {
  const baseUrl = BASE_URL.replace(/\/+$/, '');
  const base = baseUrl.endsWith('/v1') ? `${baseUrl}/` : `${baseUrl}/v1/`;
  return new URL(path.replace(/^\//, ''), base);
}

function encryptionVersionHeader(signingAlgo: SigningAlgo): Record<string, string> {
  return signingAlgo === 'ed25519' ? { 'X-Encryption-Version': '2' } : {};
}

interface ChatCompletionRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  stream: boolean;
  max_tokens: number;
}

interface ChatCompletionResponse {
  id: string;
  choices: Array<{
    finish_reason?: string;
    message: {
      content?: string;
      reasoning_content?: string;
      reasoning?: string;
    };
  }>;
}

/**
 * Make HTTP request and return JSON response
 */
async function makeRequest(
  url: string,
  options: any = {},
): Promise<{ value: any; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: options.timeout || 30000
    };

    const req = client.request(requestOptions, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk) => {
        chunks.push(Buffer.from(chunk));
      });
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        const data = body.toString('utf8');
        if (res.statusCode && res.statusCode >= 400) {
          try {
            const errorDetail = JSON.parse(data);
            const error = new Error(`HTTP ${res.statusCode}: ${JSON.stringify(errorDetail)}`);
            (error as any).statusCode = res.statusCode;
            (error as any).response = data;
            reject(error);
          } catch {
            const error = new Error(`HTTP ${res.statusCode}: ${data.substring(0, 200)}`);
            (error as any).statusCode = res.statusCode;
            (error as any).response = data;
            reject(error);
          }
          return;
        }
        try {
          resolve({ value: JSON.parse(data), body });
        } catch (error) {
          reject(new Error(`Failed to parse JSON response: ${error}`));
        }
      });
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

/**
 * Fetch model public key from attestation report
 */
async function fetchModelPublicKey(
  model: string,
  signingAlgo: SigningAlgo = 'ecdsa',
): Promise<string> {
  const url = cloudApiUrl('attestation/report');
  url.searchParams.set('model', model);
  url.searchParams.set('provider', 'near');
  url.searchParams.set('signing_algo', signingAlgo);
  url.searchParams.set('include_tls_fingerprint', 'false');
  const headers = {
    Authorization: `Bearer ${API_KEY}`,
    'Accept-Encoding': 'identity',
    'x-no-aliasing': 'true',
  };
  const { value: report } = await makeRequest(url.toString(), { headers });

  if (report.model_attestations && Array.isArray(report.model_attestations)) {
    for (const attestation of report.model_attestations) {
      if (attestation.signing_public_key) {
        return attestation.signing_public_key;
      }
    }
  }

  throw new Error(`Could not find signing_public_key for model ${model} with algorithm ${signingAlgo}`);
}

/**
 * Generate ECDSA key pair
 */
function generateEcdsaKeyPair(): { privateKey: string; publicKey: string; wallet: ethers.Wallet } {
  const wallet = ethers.Wallet.createRandom();
  // Get public key (64 bytes, without 0x04 prefix)
  const publicKey = wallet.publicKey.slice(2); // Remove '0x' prefix, then remove '04' prefix
  const publicKeyHex = publicKey.slice(2); // Remove '04' prefix
  return {
    privateKey: wallet.privateKey,
    publicKey: publicKeyHex,
    wallet
  };
}

/**
 * Generate Ed25519 key pair
 * Returns Ed25519 keys; the v2 E2EE flow converts them to X25519 for ECDH.
 */
function generateEd25519KeyPair(): { privateKey: Uint8Array; publicKey: string; keyPair: nacl.SignKeyPair } {
  const keyPair = nacl.sign.keyPair();
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
  return {
    privateKey: keyPair.secretKey, // 64 bytes: seed (32) + public key (32)
    publicKey: publicKeyHex, // 32 bytes Ed25519 public key
    keyPair
  };
}

/**
 * HKDF implementation matching vllm-proxy's implementation
 * When salt is null/None, use a zero-filled salt of hash length (32 bytes for SHA256)
 */
function hkdf(ikm: Buffer, salt: Buffer | null, info: Buffer, length: number): Buffer {
  const hashLength = 32; // SHA256 output length
  const saltBuffer = salt || Buffer.alloc(hashLength); // Zero-filled if null

  // Extract: PRK = HMAC-SHA256(salt, IKM)
  const prk = crypto.createHmac('sha256', saltBuffer).update(ikm).digest();

  // Expand: OKM = HMAC-SHA256(PRK, info || 0x01) truncated to length
  const hmac = crypto.createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([0x01])); // Counter byte
  return hmac.digest().slice(0, length);
}

function ed25519V2Key(sharedSecret: Uint8Array): Buffer {
  return hkdf(
    Buffer.from(sharedSecret),
    null,
    Buffer.from('ed25519_encryption'),
    32,
  );
}

function ed25519PublicKeyToX25519(publicKeyHex: string): Uint8Array {
  const publicKey = Buffer.from(publicKeyHex, 'hex');
  if (publicKey.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  }
  const converted = ed2curve.convertPublicKey(new Uint8Array(publicKey));
  if (!converted) {
    throw new Error('Failed to convert Ed25519 public key to X25519');
  }
  return converted;
}

function ed25519SecretKeyToX25519(privateKey: Uint8Array): Uint8Array {
  const signingKey = nacl.sign.keyPair.fromSeed(privateKey.subarray(0, 32));
  const converted = ed2curve.convertSecretKey(signingKey.secretKey);
  if (!converted) {
    throw new Error('Failed to convert Ed25519 private key to X25519');
  }
  return converted;
}

/**
 * Encrypt data using ECDSA public key (ECIES)
 */
function encryptEcdsa(data: Buffer, publicKeyHex: string): Buffer {
  // Parse public key (64 bytes hex = 128 hex chars)
  const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
  if (publicKeyBytes.length !== 64) {
    throw new Error(`ECDSA public key must be 64 bytes, got ${publicKeyBytes.length}`);
  }

  // Create EC public key point (add 0x04 prefix for uncompressed)
  const publicKeyPoint = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);

  // Generate ephemeral key pair
  const ephemeralWallet = ethers.Wallet.createRandom();
  const ephemeralPrivateKey = Buffer.from(ephemeralWallet.privateKey.slice(2), 'hex');

  // Perform ECDH using Node.js crypto
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(ephemeralPrivateKey);
  let sharedSecret: Buffer;
  try {
    sharedSecret = ecdh.computeSecret(publicKeyPoint);
  } catch (e) {
    // Fallback: derive shared secret using hash-based method
    // This is a simplified fallback - in production, proper ECDH should be used
    sharedSecret = crypto.createHash('sha256')
      .update(ephemeralPrivateKey)
      .update(publicKeyBytes)
      .digest();
  }

  // Derive AES key using HKDF
  // HKDF(algorithm=SHA256, length=32, salt=None, info=b"ecdsa_encryption")
  const aesKey = hkdf(
    sharedSecret,
    null, // salt (zero-filled 32 bytes)
    Buffer.from('ecdsa_encryption'), // info
    32 // length
  );

  // Encrypt with AES-GCM
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: [ephemeral_public_key (65 bytes)][nonce (12 bytes)][ciphertext + auth_tag]
  // vllm-proxy's AESGCM.encrypt() includes auth tag in ciphertext, so we append it here
  const ciphertextWithAuthTag = Buffer.concat([encrypted, authTag]);
  const ephemeralPublicKeyFull = Buffer.from(ephemeralWallet.publicKey.slice(2), 'hex');
  return Buffer.concat([ephemeralPublicKeyFull, nonce, ciphertextWithAuthTag]);
}

/**
 * Decrypt data using ECDSA private key
 */
function decryptEcdsa(encryptedData: Buffer, privateKey: string): Buffer {
  if (encryptedData.length < 93) {
    throw new Error('Encrypted data too short');
  }

  // Extract components
  // Format: [ephemeral_public_key (65 bytes)][nonce (12 bytes)][ciphertext_with_auth_tag]
  // vllm-proxy's AESGCM.encrypt() includes auth tag in ciphertext (last 16 bytes)
  const ephemeralPublicKey = encryptedData.slice(0, 65);
  const nonce = encryptedData.slice(65, 77);
  const ciphertextWithAuthTag = encryptedData.slice(77);

  // Perform ECDH using Node.js crypto
  const wallet = new ethers.Wallet(privateKey);
  const privateKeyBytes = Buffer.from(wallet.privateKey.slice(2), 'hex');
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKeyBytes);
  let sharedSecret: Buffer;
  try {
    sharedSecret = ecdh.computeSecret(ephemeralPublicKey);
  } catch (e) {
    // Fallback: derive shared secret using hash-based method
    sharedSecret = crypto.createHash('sha256')
      .update(privateKeyBytes)
      .update(ephemeralPublicKey.slice(1)) // Remove 0x04 prefix
      .digest();
  }

  // Derive AES key using HKDF
  // HKDF(algorithm=SHA256, length=32, salt=None, info=b"ecdsa_encryption")
  const aesKey = hkdf(
    sharedSecret,
    null, // salt (zero-filled 32 bytes)
    Buffer.from('ecdsa_encryption'), // info
    32 // length
  );

  // Decrypt with AES-GCM
  // Extract auth tag from end of ciphertext (last 16 bytes)
  const authTag = ciphertextWithAuthTag.slice(ciphertextWithAuthTag.length - 16);
  const ciphertext = ciphertextWithAuthTag.slice(0, ciphertextWithAuthTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Encrypt data using the Ed25519 E2EE v2 protocol.
 *
 * It converts the recipient's Ed25519 key to X25519, then uses X25519 ECDH,
 * HKDF-SHA256, and XChaCha20-Poly1305. The wire format is
 * [ephemeral X25519 public key][24-byte nonce][ciphertext + tag].
 */
function encryptEd25519(data: Buffer, publicKeyHex: string): Buffer {
  const recipientPublicKey = ed25519PublicKeyToX25519(publicKeyHex);
  const ephemeralSecretKey = nacl.randomBytes(32);
  const ephemeralPublicKey = nacl.scalarMult.base(ephemeralSecretKey);
  const key = ed25519V2Key(
    nacl.scalarMult(ephemeralSecretKey, recipientPublicKey),
  );
  const nonce = nacl.randomBytes(24);
  const encrypted = xchacha20poly1305(key, nonce).encrypt(data);
  return Buffer.concat([
    Buffer.from(ephemeralPublicKey),
    Buffer.from(nonce),
    Buffer.from(encrypted)
  ]);
}

/**
 * Decrypt data using the Ed25519 E2EE v2 protocol.
 */
function decryptEd25519(encryptedData: Buffer, privateKey: Uint8Array): Buffer {
  if (encryptedData.length < 72) {
    throw new Error('Encrypted data too short');
  }

  const ephemeralPublicKey = encryptedData.slice(0, 32);
  const nonce = encryptedData.slice(32, 56);
  const ciphertext = encryptedData.slice(56);
  const key = ed25519V2Key(
    nacl.scalarMult(
      ed25519SecretKeyToX25519(privateKey),
      new Uint8Array(ephemeralPublicKey),
    ),
  );
  return Buffer.from(
    xchacha20poly1305(key, new Uint8Array(nonce)).decrypt(ciphertext),
  );
}

/**
 * Encrypt message content
 */
function encryptMessageContent(
  messageContent: string,
  modelPublicKey: string,
  signingAlgo: SigningAlgo,
): string {
  const data = Buffer.from(messageContent, 'utf-8');
  let encrypted: Buffer;
  if (signingAlgo === 'ecdsa') {
    encrypted = encryptEcdsa(data, modelPublicKey);
  } else if (signingAlgo === 'ed25519') {
    encrypted = encryptEd25519(data, modelPublicKey);
  } else {
    throw new Error(`Unsupported signing algorithm: ${signingAlgo}`);
  }
  return encrypted.toString('hex');
}

/**
 * Decrypt message content
 */
function decryptMessageContent(
  encryptedHex: string,
  clientPrivateKey: any,
  signingAlgo: SigningAlgo,
): string {
  const encryptedData = Buffer.from(encryptedHex, 'hex');
  let decrypted: Buffer;
  if (signingAlgo === 'ecdsa') {
    decrypted = decryptEcdsa(encryptedData, clientPrivateKey);
  } else if (signingAlgo === 'ed25519') {
    decrypted = decryptEd25519(encryptedData, clientPrivateKey);
  } else {
    throw new Error(`Unsupported signing algorithm: ${signingAlgo}`);
  }
  return decrypted.toString('utf-8');
}

/**
 * Encrypted streaming example
 */
async function encryptedStreamingExample(
  model: string,
  signingAlgo: SigningAlgo = 'ecdsa',
): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Encrypted Streaming Example (${signingAlgo.toUpperCase()})`);
  console.log(`${'='.repeat(60)}`);

  // Fetch model public key
  let modelPubKey: string;
  try {
    modelPubKey = await fetchModelPublicKey(model, signingAlgo);
    console.log(`✓ Fetched model public key: ${modelPubKey}`);
  } catch (error) {
    console.log(`✗ Failed to fetch model public key: ${error}`);
    return;
  }

  // Generate client key pair
  let clientPubKey: string;
  let clientPrivKey: any;
  try {
    if (signingAlgo === 'ecdsa') {
      const keyPair = generateEcdsaKeyPair();
      clientPubKey = keyPair.publicKey;
      clientPrivKey = keyPair.privateKey;
    } else {
      const keyPair = generateEd25519KeyPair();
      clientPubKey = keyPair.publicKey;
      clientPrivKey = keyPair.privateKey;
    }
    console.log(`✓ Generated client key pair: ${clientPubKey.substring(0, 32)}...`);
  } catch (error) {
    console.log(`✗ Failed to generate client key pair: ${error}`);
    return;
  }

  // Prepare message
  const originalContent = 'Hello, how are you?';
  let encryptedContent: string;
  try {
    encryptedContent = encryptMessageContent(originalContent, modelPubKey, signingAlgo);
    console.log(`✓ Encrypted message content: ${encryptedContent}`);
  } catch (error) {
    console.log(`✗ Failed to encrypt message: ${error}`);
    return;
  }

  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: encryptedContent }],
    stream: true,
    max_tokens: MAX_TOKENS
  };

  const bodyJson = JSON.stringify(body);

  return new Promise((resolve, reject) => {
    const urlObj = cloudApiUrl('chat/completions');
    const isHttps = urlObj.protocol === 'https:';
    const client = isHttps ? https : http;

    const requestOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
        'X-Signing-Algo': signingAlgo,
        'X-Client-Pub-Key': clientPubKey,
        'X-Model-Pub-Key': modelPubKey,
        'Accept-Encoding': 'identity',
        'x-no-aliasing': 'true',
        ...encryptionVersionHeader(signingAlgo),
      },
      timeout: 30000
    };

    const req = client.request(requestOptions, (res) => {
      if (res.statusCode && res.statusCode !== 200) {
        let errorData = '';
        res.on('data', (chunk) => {
          errorData += chunk.toString();
        });
        res.on('end', () => {
          console.log(`✗ Request failed: HTTP ${res.statusCode}`);
          console.log(`  Status code: ${res.statusCode}`);
          try {
            const errorDetail = JSON.parse(errorData);
            console.log(`  Error detail: ${JSON.stringify(errorDetail, null, 2)}`);
          } catch {
            console.log(`  Response text: ${errorData.substring(0, 200)}`);
          }
          reject(new Error(`HTTP ${res.statusCode}: ${errorData}`));
        });
        return;
      }

      let buffer = '';
      const responseChunks: Buffer[] = [];
      let chatId: string | null = null;
      let decryptedContent = '';
      const decryptionFailures: string[] = [];

      console.log(`✓ Request sent successfully (HTTP ${res.statusCode || 200})`);
      console.log('\nReceiving stream...');

      res.on('data', (chunk) => {
        const chunkBytes = Buffer.from(chunk);
        const chunkText = chunkBytes.toString('utf8');
        responseChunks.push(chunkBytes);
        buffer += chunkText;

        let newlineIndex;
        while ((newlineIndex = buffer.indexOf('\n')) !== -1) {
          const line = buffer.substring(0, newlineIndex).trim();
          buffer = buffer.substring(newlineIndex + 1);

          if (line.length === 0 || line.startsWith(':')) {
            continue;
          }

          if (line.startsWith('data: ') && chatId === null) {
            const dataStr = line.substring(6);
            if (dataStr === '[DONE]') {
              continue;
            }
            try {
              const data = JSON.parse(dataStr);
              if (data.id) {
                chatId = data.id;
                console.log(`✓ Chat ID: ${chatId}`);
              }
            } catch (error) {
              // Ignore parsing errors
            }
          }

          // Content and reasoning fields are independently encrypted in every
          // streaming event.
          if (line.startsWith('data: {') && !line.includes('[DONE]')) {
            try {
              const data = JSON.parse(line.substring(6));
              if (data.choices && data.choices.length > 0) {
                const delta = data.choices[0].delta;
                for (const field of ['content', 'reasoning_content', 'reasoning']) {
                  const encryptedField = delta?.[field];
                  if (typeof encryptedField !== 'string' || encryptedField.length === 0) {
                    continue;
                  }
                  try {
                    const decryptedChunk = decryptMessageContent(
                      encryptedField,
                      clientPrivKey,
                      signingAlgo,
                    );
                    if (field === 'content') decryptedContent += decryptedChunk;
                    process.stdout.write(`  Decrypted ${field} chunk: ${decryptedChunk}\n`);
                  } catch (error) {
                    const detail = error instanceof Error ? error.message : String(error);
                    console.log(`✗ Failed to decrypt ${field}: ${detail}`);
                    decryptionFailures.push(`${field}: ${detail}`);
                  }
                }
              }
            } catch (error) {
              // Ignore parsing errors
            }
          }
        }
      });

      res.on('end', async () => {
        if (!chatId) {
          console.log(`✗ Failed to extract chat ID from streaming response`);
          reject(new Error('Failed to extract chat ID from streaming response'));
          return;
        }
        console.log(`\n\n✓ Complete decrypted response: ${decryptedContent}`);
        const responseBody = Buffer.concat(responseChunks);
        console.log(`✓ Total response length: ${responseBody.length} bytes`);
        try {
          await verifyCompletion({
            id: chatId,
            requestBody: Buffer.from(bodyJson, 'utf8'),
            responseBody,
            label: `Encrypted Streaming (${signingAlgo.toUpperCase()})`,
            signingAlgo,
          });
          if (decryptionFailures.length > 0) {
            throw new Error(
              `Could not decrypt ${decryptionFailures.length} encrypted stream field(s): ${decryptionFailures.join('; ')}`,
            );
          }
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });

    req.on('error', (error) => {
      console.log(`✗ Request failed: ${error}`);
      reject(error);
    });
    req.on('timeout', () => {
      req.destroy();
      console.log(`✗ Request timeout`);
      reject(new Error('Request timeout'));
    });

    req.write(bodyJson);
    req.end();
  });
}

/**
 * Encrypted non-streaming example
 */
async function encryptedNonStreamingExample(
  model: string,
  signingAlgo: SigningAlgo = 'ecdsa',
): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Encrypted Non-Streaming Example (${signingAlgo.toUpperCase()})`);
  console.log(`${'='.repeat(60)}`);

  // Fetch model public key
  let modelPubKey: string;
  try {
    modelPubKey = await fetchModelPublicKey(model, signingAlgo);
    console.log(`✓ Fetched model public key: ${modelPubKey}`);
  } catch (error) {
    console.log(`✗ Failed to fetch model public key: ${error}`);
    return;
  }

  // Generate client key pair
  let clientPubKey: string;
  let clientPrivKey: any;
  try {
    if (signingAlgo === 'ecdsa') {
      const keyPair = generateEcdsaKeyPair();
      clientPubKey = keyPair.publicKey;
      clientPrivKey = keyPair.privateKey;
    } else {
      const keyPair = generateEd25519KeyPair();
      clientPubKey = keyPair.publicKey;
      clientPrivKey = keyPair.privateKey;
    }
    console.log(`✓ Generated client key pair: ${clientPubKey.substring(0, 32)}...`);
  } catch (error) {
    console.log(`✗ Failed to generate client key pair: ${error}`);
    return;
  }

  // Prepare message
  const originalContent = 'Hello, how are you?';
  let encryptedContent: string;
  try {
    encryptedContent = encryptMessageContent(originalContent, modelPubKey, signingAlgo);
    console.log(`✓ Encrypted message content: ${encryptedContent}`);
  } catch (error) {
    console.log(`✗ Failed to encrypt message: ${error}`);
    return;
  }

  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: encryptedContent }],
    stream: false,
    max_tokens: MAX_TOKENS
  };

  const bodyJson = JSON.stringify(body);

  let response: any;
  let responseBody: Buffer;
  try {
    const result = await makeRequest(cloudApiUrl('chat/completions').toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
        'X-Signing-Algo': signingAlgo,
        'X-Client-Pub-Key': clientPubKey,
        'X-Model-Pub-Key': modelPubKey,
        'Accept-Encoding': 'identity',
        'x-no-aliasing': 'true',
        ...encryptionVersionHeader(signingAlgo),
      },
      body: bodyJson
    });
    response = result.value;
    responseBody = result.body;
    console.log(`✓ Request sent successfully`);
  } catch (error: any) {
    console.log(`✗ Request failed: ${error}`);
    if (error.statusCode) {
      console.log(`  Status code: ${error.statusCode}`);
    }
    if (error.message) {
      console.log(`  Error: ${error.message}`);
    }
    if (error.response) {
      try {
        const errorDetail = JSON.parse(error.response);
        console.log(`  Error detail: ${JSON.stringify(errorDetail, null, 2)}`);
      } catch {
        console.log(`  Response text: ${error.response.substring(0, 200)}`);
      }
    }
    return;
  }

  const payload: ChatCompletionResponse = response;
  const chatId = payload.id || 'unknown';
  console.log(`✓ Chat ID: ${chatId}`);

  // Check finish_reason to see if response was truncated
  if (payload.choices && payload.choices.length > 0) {
    const choice = payload.choices[0];
    const finishReason = choice.finish_reason || 'unknown';
    console.log(`✓ Finish reason: ${finishReason}`);
    if (finishReason === 'length') {
      console.log(`  ⚠ Response was truncated due to max_tokens limit`);
    }
  }

  // Decrypt response content (including all encrypted fields)
  const decryptionFailures: string[] = [];
  if (payload.choices && payload.choices.length > 0) {
    const message = payload.choices[0].message;

    // Decrypt all encrypted fields: content, reasoning_content, reasoning
    const decryptedFields: Record<string, string> = {};
    for (const field of ['content', 'reasoning_content', 'reasoning']) {
      const fieldValue = (message as any)[field];
      if (fieldValue) {
        // Check if it looks like encrypted hex (even length, hex chars, reasonably long)
        if (typeof fieldValue === 'string' && fieldValue.length > 64) {
          if (fieldValue.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(fieldValue)) {
            try {
              const decryptedValue = decryptMessageContent(fieldValue, clientPrivKey, signingAlgo);
              decryptedFields[field] = decryptedValue;
              console.log(`✓ Decrypted ${field} (${decryptedValue.length} chars)`);
            } catch (error) {
              const detail = error instanceof Error ? error.message : String(error);
              console.log(`✗ Failed to decrypt ${field}: ${detail}`);
              console.log(`  Encrypted ${field} (first 100 chars): ${fieldValue.substring(0, 100)}`);
              decryptionFailures.push(`${field}: ${detail}`);
            }
          } else {
            // Not encrypted, just plain text
            decryptedFields[field] = fieldValue;
            console.log(`✓ ${field} (plain text, ${fieldValue.length} chars)`);
          }
        } else if (fieldValue) {
          // Short value or not hex - might be plain text
          decryptedFields[field] = fieldValue;
          console.log(`✓ ${field} (plain text, ${fieldValue.length} chars)`);
        }
      }
    }

    if (Object.keys(decryptedFields).length > 0) {
      // Show complete decrypted response
      if (decryptedFields.content) {
        const content = decryptedFields.content;
        console.log(`\n✓ Complete decrypted response (${content.length} characters):`);
        console.log(`  ${content}`);
        if (decryptedFields.reasoning_content) {
          const reasoning = decryptedFields.reasoning_content;
          console.log(`\n✓ Reasoning content (${reasoning.length} characters):`);
          console.log(`  ${reasoning}`);
        }
        if (decryptedFields.reasoning) {
          const reasoningAlt = decryptedFields.reasoning;
          console.log(`\n✓ Reasoning (alt) (${reasoningAlt.length} characters):`);
          console.log(`  ${reasoningAlt}`);
        }
      } else {
        console.log(`\n⚠ No content field found in decrypted fields`);
      }
    } else {
      console.log(`\n⚠ No encrypted fields found to decrypt`);
      console.log(`  Message keys: ${Object.keys(message)}`);
      console.log(`  Message: ${JSON.stringify(message, null, 2)}`);
    }
  } else {
    console.log('✗ No choices in response');
    console.log(`  Response: ${JSON.stringify(payload, null, 2)}`);
  }

  await verifyCompletion({
    id: chatId,
    requestBody: Buffer.from(bodyJson, 'utf8'),
    responseBody,
    label: `Encrypted Non-Streaming (${signingAlgo.toUpperCase()})`,
    signingAlgo,
  });
  if (decryptionFailures.length > 0) {
    throw new Error(
      `Could not decrypt ${decryptionFailures.length} encrypted response field(s): ${decryptionFailures.join('; ')}`,
    );
  }
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'deepseek-ai/DeepSeek-V3.1';
  const signingAlgoIndex = args.indexOf('--signing-algo');
  const requestedSigningAlgo =
    signingAlgoIndex !== -1 && args[signingAlgoIndex + 1]
      ? args[signingAlgoIndex + 1]
      : 'ecdsa';
  if (requestedSigningAlgo !== 'ecdsa' && requestedSigningAlgo !== 'ed25519') {
    throw new Error('Unsupported signing algorithm; expected ecdsa or ed25519');
  }
  const signingAlgo: SigningAlgo = requestedSigningAlgo;
  const testBoth = args.includes('--test-both');

  if (!API_KEY) {
    console.log('Error: API_KEY environment variable is required');
    console.log('Set it with: export API_KEY=your-api-key');
    return;
  }

  if (testBoth) {
    // Test both algorithms
    await encryptedStreamingExample(model, 'ecdsa');
    await encryptedNonStreamingExample(model, 'ecdsa');
    await encryptedStreamingExample(model, 'ed25519');
    await encryptedNonStreamingExample(model, 'ed25519');
  } else {
    await encryptedStreamingExample(model, signingAlgo);
    await encryptedNonStreamingExample(model, signingAlgo);
  }
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  fetchModelPublicKey,
  generateEcdsaKeyPair,
  generateEd25519KeyPair,
  encryptEcdsa,
  decryptEcdsa,
  encryptEd25519,
  decryptEd25519,
  encryptMessageContent,
  decryptMessageContent,
  encryptedStreamingExample,
  encryptedNonStreamingExample,
};
