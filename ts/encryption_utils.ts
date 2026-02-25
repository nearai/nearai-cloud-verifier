/**
 * Shared helpers for NEAR AI Cloud E2E encryption demos.
 *
 * Kept dependency-light and usable by both encrypted_chat_verifier.ts and
 * encrypted_image_verifier.ts.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import * as ed2curve from 'ed2curve';

export type SigningAlgo = 'ecdsa' | 'ed25519';

/**
 * Make HTTP request and return JSON response.
 * (Used by non-streaming examples and attestation key fetch.)
 */
export async function makeRequest(url: string, options: any = {}): Promise<any> {
  return await new Promise((resolve, reject) => {
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
      let data = '';
      res.on('data', (chunk) => {
        data += chunk.toString();
      });
      res.on('end', () => {
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
          resolve(JSON.parse(data));
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

export async function fetchModelPublicKey(
  baseUrl: string,
  apiKey: string,
  model: string,
  signingAlgo: SigningAlgo = 'ecdsa'
): Promise<string> {
  const url = `${baseUrl}/v1/attestation/report?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`;
  const headers = { Authorization: `Bearer ${apiKey}` };
  const report = await makeRequest(url, { headers });

  if (report.model_attestations && Array.isArray(report.model_attestations)) {
    for (const attestation of report.model_attestations) {
      if (attestation.signing_public_key) {
        return attestation.signing_public_key;
      }
    }
  }

  throw new Error(`Could not find signing_public_key for model ${model} with algorithm ${signingAlgo}`);
}

export function generateEcdsaKeyPair(): { privateKey: string; publicKey: string; wallet: ethers.Wallet } {
  const wallet = ethers.Wallet.createRandom();
  // ethers Wallet publicKey is 0x04 + 64-byte uncompressed; server wants 64 bytes (no 0x04)
  const publicKey = wallet.publicKey.slice(2); // Remove '0x'
  const publicKeyHex = publicKey.slice(2); // Remove '04'
  return { privateKey: wallet.privateKey, publicKey: publicKeyHex, wallet };
}

export function generateEd25519KeyPair(): { privateKey: Uint8Array; publicKey: string; keyPair: nacl.SignKeyPair } {
  const keyPair = nacl.sign.keyPair();
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
  return { privateKey: keyPair.secretKey, publicKey: publicKeyHex, keyPair };
}

/**
 * HKDF implementation matching vllm-proxy's implementation.
 * When salt is null/None, use a zero-filled salt of hash length (32 bytes for SHA256).
 */
function hkdf(ikm: Buffer, salt: Buffer | null, info: Buffer, length: number): Buffer {
  const hashLength = 32;
  const saltBuffer = salt || Buffer.alloc(hashLength);

  const prk = crypto.createHmac('sha256', saltBuffer).update(ikm).digest();

  const hmac = crypto.createHmac('sha256', prk);
  hmac.update(info);
  hmac.update(Buffer.from([0x01]));
  return hmac.digest().slice(0, length);
}

export function encryptEcdsa(data: Buffer, publicKeyHex: string): Buffer {
  const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
  if (publicKeyBytes.length !== 64) {
    throw new Error(`ECDSA public key must be 64 bytes, got ${publicKeyBytes.length}`);
  }

  const publicKeyPoint = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);

  const ephemeralWallet = ethers.Wallet.createRandom();
  const ephemeralPrivateKey = Buffer.from(ephemeralWallet.privateKey.slice(2), 'hex');

  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(ephemeralPrivateKey);
  let sharedSecret: Buffer;
  try {
    sharedSecret = ecdh.computeSecret(publicKeyPoint);
  } catch {
    // Fallback kept for parity with existing code (should not be relied on in production).
    sharedSecret = crypto.createHash('sha256').update(ephemeralPrivateKey).update(publicKeyBytes).digest();
  }

  const aesKey = hkdf(sharedSecret, null, Buffer.from('ecdsa_encryption'), 32);

  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const ciphertextWithAuthTag = Buffer.concat([encrypted, authTag]);
  const ephemeralPublicKeyFull = Buffer.from(ephemeralWallet.publicKey.slice(2), 'hex'); // 65 bytes (0x04 + xy)
  return Buffer.concat([ephemeralPublicKeyFull, nonce, ciphertextWithAuthTag]);
}

export function decryptEcdsa(encryptedData: Buffer, privateKey: string): Buffer {
  if (encryptedData.length < 93) {
    throw new Error('Encrypted data too short');
  }

  const ephemeralPublicKey = encryptedData.slice(0, 65);
  const nonce = encryptedData.slice(65, 77);
  const ciphertextWithAuthTag = encryptedData.slice(77);

  const wallet = new ethers.Wallet(privateKey);
  const privateKeyBytes = Buffer.from(wallet.privateKey.slice(2), 'hex');
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(privateKeyBytes);
  let sharedSecret: Buffer;
  try {
    sharedSecret = ecdh.computeSecret(ephemeralPublicKey);
  } catch {
    sharedSecret = crypto.createHash('sha256').update(privateKeyBytes).update(ephemeralPublicKey.slice(1)).digest();
  }

  const aesKey = hkdf(sharedSecret, null, Buffer.from('ecdsa_encryption'), 32);

  const authTag = ciphertextWithAuthTag.slice(ciphertextWithAuthTag.length - 16);
  const ciphertext = ciphertextWithAuthTag.slice(0, ciphertextWithAuthTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function encryptEd25519(data: Buffer, publicKeyHex: string): Buffer {
  const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
  }

  const ed25519PublicKey = new Uint8Array(publicKeyBytes);
  const x25519PublicKey = ed2curve.convertPublicKey(ed25519PublicKey);
  if (!x25519PublicKey) {
    throw new Error('Failed to convert Ed25519 public key to X25519');
  }

  const ephemeralKeyPair = nacl.box.keyPair();
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.box(data, nonce, x25519PublicKey, ephemeralKeyPair.secretKey);

  return Buffer.concat([Buffer.from(ephemeralKeyPair.publicKey), Buffer.from(nonce), Buffer.from(encrypted)]);
}

export function decryptEd25519(encryptedData: Buffer, privateKey: Uint8Array): Buffer {
  if (encryptedData.length < 72) {
    throw new Error('Encrypted data too short');
  }

  const ephemeralPublicKey = encryptedData.slice(0, 32);
  const nonce = encryptedData.slice(32, 56);
  const ciphertext = encryptedData.slice(56);

  const seed = privateKey.slice(0, 32);
  const signingKeyPair = nacl.sign.keyPair.fromSeed(seed);
  const x25519SecretKey = ed2curve.convertSecretKey(signingKeyPair.secretKey);
  if (!x25519SecretKey) {
    throw new Error('Failed to convert Ed25519 private key to X25519');
  }
  const x25519KeyPair = nacl.box.keyPair.fromSecretKey(x25519SecretKey);

  const decrypted = nacl.box.open(
    new Uint8Array(ciphertext),
    new Uint8Array(nonce),
    new Uint8Array(ephemeralPublicKey),
    x25519KeyPair.secretKey
  );
  if (!decrypted) {
    throw new Error('Decryption failed');
  }
  return Buffer.from(decrypted);
}

export function encryptText(text: string, modelPublicKey: string, signingAlgo: SigningAlgo): string {
  const data = Buffer.from(text, 'utf-8');
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

export function decryptText(encryptedHex: string, clientPrivateKey: any, signingAlgo: SigningAlgo): string {
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

