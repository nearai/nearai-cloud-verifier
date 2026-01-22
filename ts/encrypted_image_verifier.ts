#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud End-to-End Encryption Test for Image Generation
 * Test end-to-end encryption for image generation.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import * as ed2curve from 'ed2curve';
import {
  verifyImage,
} from './image_verifier';

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';

interface ImageGenerationRequest {
  model: string;
  prompt: string;
  size?: string;
  n?: number;
  response_format?: string;
  negative_prompt?: string;
  num_inference_steps?: number;
  guidance_scale?: number;
  true_cfg_scale?: number;
  seed?: number;
}

interface ImageGenerationResponse {
  id: string;
  created: number;
  data: Array<{
    b64_json?: string;
    url?: string;
    revised_prompt?: string;
  }>;
}

/**
 * Make HTTP request and return JSON response
 */
async function makeRequest(url: string, options: any = {}): Promise<any> {
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

/**
 * Fetch model public key from attestation report
 */
async function fetchModelPublicKey(model: string, signingAlgo: string = 'ecdsa'): Promise<string> {
  const url = `${BASE_URL}/v1/attestation/report?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`;
  const headers = { Authorization: `Bearer ${API_KEY}` };
  const report = await makeRequest(url, { headers });

  // Try to get signing_public_key from model_attestations
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
 * Returns Ed25519 keys (not X25519) - these can be converted to X25519 for Box encryption
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
 * Encrypt data using Ed25519 public key (via X25519 + ChaCha20-Poly1305)
 */
function encryptEd25519(data: Buffer, publicKeyHex: string): Buffer {
  const publicKeyBytes = Buffer.from(publicKeyHex, 'hex');
  if (publicKeyBytes.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKeyBytes.length}`);
  }

  // Convert Ed25519 public key to X25519 public key using ed2curve
  const ed25519PublicKey = new Uint8Array(publicKeyBytes);
  const x25519PublicKey = ed2curve.convertPublicKey(ed25519PublicKey);
  
  if (!x25519PublicKey) {
    throw new Error('Failed to convert Ed25519 public key to X25519');
  }

  // Generate ephemeral key pair
  const ephemeralKeyPair = nacl.box.keyPair();

  // Encrypt using Box
  const nonce = nacl.randomBytes(24);
  const encrypted = nacl.box(data, nonce, x25519PublicKey, ephemeralKeyPair.secretKey);

  // Format: [ephemeral_public_key (32 bytes)][nonce (24 bytes)][ciphertext]
  return Buffer.concat([
    Buffer.from(ephemeralKeyPair.publicKey),
    Buffer.from(nonce),
    Buffer.from(encrypted)
  ]);
}

/**
 * Decrypt data using Ed25519 private key
 */
function decryptEd25519(encryptedData: Buffer, privateKey: Uint8Array): Buffer {
  if (encryptedData.length < 72) {
    throw new Error('Encrypted data too short');
  }

  // Extract components
  const ephemeralPublicKey = encryptedData.slice(0, 32);
  const nonce = encryptedData.slice(32, 56);
  const ciphertext = encryptedData.slice(56);

  // Convert Ed25519 private key to X25519 using ed2curve
  // The private key should be 32 bytes (seed) or 64 bytes (seed + public key)
  const seed = privateKey.slice(0, 32);
  const signingKeyPair = nacl.sign.keyPair.fromSeed(seed);
  
  // Convert Ed25519 secret key to X25519 secret key
  const x25519SecretKey = ed2curve.convertSecretKey(signingKeyPair.secretKey);
  
  if (!x25519SecretKey) {
    throw new Error('Failed to convert Ed25519 private key to X25519');
  }

  // Create X25519 keypair from the converted secret key
  const x25519KeyPair = nacl.box.keyPair.fromSecretKey(x25519SecretKey);

  // Decrypt using Box
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

/**
 * Encrypt prompt
 */
function encryptPrompt(prompt: string, modelPublicKey: string, signingAlgo: string): string {
  const data = Buffer.from(prompt, 'utf-8');
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
 * Decrypt prompt
 */
function decryptPrompt(encryptedHex: string, clientPrivateKey: any, signingAlgo: string): string {
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
 * Encrypted image generation example
 */
async function encryptedImageGenerationExample(model: string, signingAlgo: string = 'ecdsa'): Promise<void> {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`Encrypted Image Generation Example (${signingAlgo.toUpperCase()})`);
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

  // Prepare prompt
  const originalPrompt = 'a beautiful sunset over mountains';
  let encryptedPrompt: string;
  try {
    encryptedPrompt = encryptPrompt(originalPrompt, modelPubKey, signingAlgo);
    console.log(`✓ Encrypted prompt: ${encryptedPrompt}`);
  } catch (error) {
    console.log(`✗ Failed to encrypt prompt: ${error}`);
    return;
  }

  const body: ImageGenerationRequest = {
    model,
    prompt: encryptedPrompt,
    size: '1024x1024',
    n: 1,
    response_format: 'b64_json'
  };

  const bodyJson = JSON.stringify(body);

  let response: any;
  try {
    response = await makeRequest(`${BASE_URL}/v1/images/generations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${API_KEY}`,
        'X-Signing-Algo': signingAlgo,
        'X-Client-Pub-Key': clientPubKey,
        'X-Model-Pub-Key': modelPubKey
      },
      body: bodyJson,
      timeout: 60000 // Image generation may take longer
    });
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

  const payload: ImageGenerationResponse = response;
  const imageId = payload.id || 'unknown';
  console.log(`✓ Image ID: ${imageId}`);

  // Decrypt response fields if encryption is enabled
  if (payload.data && payload.data.length > 0) {
    console.log(`✓ Generated ${payload.data.length} image(s)`);
    for (let i = 0; i < payload.data.length; i++) {
      const item = payload.data[i];
      
      // Decrypt b64_json if present and encrypted
      if (item.b64_json) {
        const encryptedB64 = item.b64_json;
        // Check if it looks like encrypted hex (even length, hex chars, reasonably long)
        if (typeof encryptedB64 === 'string' && encryptedB64.length > 64) {
          if (encryptedB64.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(encryptedB64)) {
            try {
              const decryptedB64 = decryptPrompt(encryptedB64, clientPrivKey, signingAlgo);
              console.log(`✓ Decrypted b64_json for image ${i + 1} (${decryptedB64.length} chars)`);
              // Optionally save the decrypted image
              // const imgData = Buffer.from(decryptedB64, 'base64');
              // require('fs').writeFileSync(`decrypted_image_${i + 1}.png`, imgData);
            } catch (error) {
              console.log(`✗ Failed to decrypt b64_json for image ${i + 1}: ${error}`);
            }
          }
        }
      }
      
      // Decrypt revised_prompt if present and encrypted
      if (item.revised_prompt) {
        const encryptedPrompt = item.revised_prompt;
        // Check if it looks like encrypted hex
        if (typeof encryptedPrompt === 'string' && encryptedPrompt.length > 64) {
          if (encryptedPrompt.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(encryptedPrompt)) {
            try {
              const decryptedPrompt = decryptPrompt(encryptedPrompt, clientPrivKey, signingAlgo);
              console.log(`✓ Decrypted revised_prompt for image ${i + 1}: ${decryptedPrompt}`);
            } catch (error) {
              console.log(`✗ Failed to decrypt revised_prompt for image ${i + 1}: ${error}`);
            }
          }
        }
      }
    }
  }

  await verifyImage(imageId, bodyJson, JSON.stringify(response), `Encrypted Image Generation (${signingAlgo.toUpperCase()})`, model);
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'Qwen/Qwen-Image';
  const signingAlgoIndex = args.indexOf('--signing-algo');
  const signingAlgo = signingAlgoIndex !== -1 && signingAlgoIndex + 1 < args.length && args[signingAlgoIndex + 1] ? args[signingAlgoIndex + 1] : 'ecdsa';
  const testBoth = args.includes('--test-both');

  if (!API_KEY) {
    console.log('Error: API_KEY environment variable is required');
    console.log('Set it with: export API_KEY=your-api-key');
    return;
  }

  if (testBoth) {
    // Test both algorithms
    await encryptedImageGenerationExample(model, 'ecdsa');
    await encryptedImageGenerationExample(model, 'ed25519');
  } else {
    await encryptedImageGenerationExample(model, signingAlgo);
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
  encryptPrompt,
  decryptPrompt,
  encryptedImageGenerationExample,
};

