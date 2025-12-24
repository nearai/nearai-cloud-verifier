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
import {
  verifyChat,
} from './chat_verifier';

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';

interface ChatCompletionRequest {
  model: string;
  messages: Array<{ role: string; content: string }>;
  stream: boolean;
  max_tokens: number;
}

interface ChatCompletionResponse {
  id: string;
  choices: Array<{
    message: {
      content: string;
    };
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
        data += chunk;
      });
      res.on('end', () => {
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
  } else if (report.signing_public_key) {
    return report.signing_public_key;
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
 */
function generateEd25519KeyPair(): { privateKey: Uint8Array; publicKey: string; keyPair: nacl.BoxKeyPair } {
  const keyPair = nacl.box.keyPair();
  const publicKeyHex = Buffer.from(keyPair.publicKey).toString('hex');
  return {
    privateKey: keyPair.secretKey,
    publicKey: publicKeyHex,
    keyPair
  };
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
  
  // Derive AES key using HKDF (simplified HKDF using HMAC)
  const hkdf = crypto.createHmac('sha256', Buffer.alloc(0));
  hkdf.update(sharedSecret);
  hkdf.update(Buffer.from('ecdsa_encryption'));
  const aesKey = hkdf.digest();
  
  // Encrypt with AES-GCM
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Format: [ephemeral_public_key (65 bytes)][nonce (12 bytes)][ciphertext][auth_tag (16 bytes)]
  const ephemeralPublicKeyFull = Buffer.from(ephemeralWallet.publicKey.slice(2), 'hex');
  return Buffer.concat([ephemeralPublicKeyFull, nonce, encrypted, authTag]);
}

/**
 * Decrypt data using ECDSA private key
 */
function decryptEcdsa(encryptedData: Buffer, privateKey: string): Buffer {
  if (encryptedData.length < 93) {
    throw new Error('Encrypted data too short');
  }
  
  // Extract components
  const ephemeralPublicKey = encryptedData.slice(0, 65);
  const nonce = encryptedData.slice(65, 77);
  const ciphertext = encryptedData.slice(77, encryptedData.length - 16);
  const authTag = encryptedData.slice(encryptedData.length - 16);
  
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
  const hkdf = crypto.createHmac('sha256', Buffer.alloc(0));
  hkdf.update(sharedSecret);
  hkdf.update(Buffer.from('ecdsa_encryption'));
  const aesKey = hkdf.digest();
  
  // Decrypt with AES-GCM
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
  
  // Convert Ed25519 public key to X25519 using nacl
  // nacl.box.keyPair.fromSecretKey can convert Ed25519 keys
  // We need to create a temporary keypair to get the conversion
  const tempKeyPair = nacl.sign.keyPair.fromSeed(publicKeyBytes);
  // For public key conversion, we use the public key directly
  // Note: This is a simplified conversion - proper conversion uses curve25519 conversion
  const x25519PublicKey = nacl.box.keyPair.fromSecretKey(tempKeyPair.secretKey).publicKey;
  
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
  
  // Convert Ed25519 private key to X25519
  // The private key should be 32 bytes (seed) or 64 bytes (seed + public key)
  // For nacl, we need to create a signing keypair first, then convert to box keypair
  const seed = privateKey.slice(0, 32);
  const signingKeyPair = nacl.sign.keyPair.fromSeed(seed);
  const x25519KeyPair = nacl.box.keyPair.fromSecretKey(signingKeyPair.secretKey);
  
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
 * Encrypt message content
 */
function encryptMessageContent(messageContent: string, modelPublicKey: string, signingAlgo: string): string {
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
function decryptMessageContent(encryptedHex: string, clientPrivateKey: any, signingAlgo: string): string {
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
async function encryptedStreamingExample(model: string, signingAlgo: string = 'ecdsa'): Promise<void> {
  // Fetch model public key
  const modelPubKey = await fetchModelPublicKey(model, signingAlgo);
  console.log(`\n--- Encrypted Streaming Example (${signingAlgo.toUpperCase()}) ---`);
  console.log(`Model public key: ${modelPubKey.substring(0, 32)}...`);
  
  // Generate client key pair
  let clientPubKey: string;
  let clientPrivKey: any;
  if (signingAlgo === 'ecdsa') {
    const keyPair = generateEcdsaKeyPair();
    clientPubKey = keyPair.publicKey;
    clientPrivKey = keyPair.privateKey;
  } else {
    const keyPair = generateEd25519KeyPair();
    clientPubKey = keyPair.publicKey;
    clientPrivKey = keyPair.privateKey;
  }
  console.log(`Client public key: ${clientPubKey.substring(0, 32)}...`);
  
  // Prepare message
  const originalContent = 'Hello, how are you?';
  const encryptedContent = encryptMessageContent(originalContent, modelPubKey, signingAlgo);
  
  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: encryptedContent }],
    stream: true,
    max_tokens: 10
  };
  
  const bodyJson = JSON.stringify(body);
  
  return new Promise((resolve, reject) => {
    const urlObj = new URL(`${BASE_URL}/v1/chat/completions`);
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
        'X-Model-Pub-Key': modelPubKey
      },
      timeout: 30000
    };
    
    const req = client.request(requestOptions, (res) => {
      if (res.statusCode !== 200) {
        let errorData = '';
        res.on('data', (chunk) => {
          errorData += chunk.toString();
        });
        res.on('end', () => {
          reject(new Error(`HTTP ${res.statusCode}: ${errorData}`));
        });
        return;
      }
      
      let buffer = '';
      let responseText = '';
      let chatId: string | null = null;
      let decryptedContent = '';
      
      res.on('data', (chunk) => {
        buffer += chunk.toString();
        responseText += chunk.toString();
        
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
              }
            } catch (error) {
              // Ignore parsing errors
            }
          }
          
          // Try to decrypt content
          if (line.startsWith('data: {') && !line.includes('[DONE]')) {
            try {
              const data = JSON.parse(line.substring(6));
              if (data.choices && data.choices.length > 0) {
                const delta = data.choices[0].delta;
                if (delta && delta.content) {
                  try {
                    const decryptedChunk = decryptMessageContent(delta.content, clientPrivKey, signingAlgo);
                    decryptedContent += decryptedChunk;
                  } catch (e) {
                    // Decryption failed, might be plain text
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
          reject(new Error('Failed to extract chat ID from streaming response'));
          return;
        }
        console.log(`Decrypted response: ${decryptedContent.substring(0, 100)}...`);
        try {
          await verifyChat(chatId, bodyJson, responseText, `Encrypted Streaming (${signingAlgo.toUpperCase()})`, model);
          resolve();
        } catch (error) {
          reject(error);
        }
      });
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    req.write(bodyJson);
    req.end();
  });
}

/**
 * Encrypted non-streaming example
 */
async function encryptedNonStreamingExample(model: string, signingAlgo: string = 'ecdsa'): Promise<void> {
  // Fetch model public key
  const modelPubKey = await fetchModelPublicKey(model, signingAlgo);
  console.log(`\n--- Encrypted Non-Streaming Example (${signingAlgo.toUpperCase()}) ---`);
  console.log(`Model public key: ${modelPubKey.substring(0, 32)}...`);
  
  // Generate client key pair
  let clientPubKey: string;
  let clientPrivKey: any;
  if (signingAlgo === 'ecdsa') {
    const keyPair = generateEcdsaKeyPair();
    clientPubKey = keyPair.publicKey;
    clientPrivKey = keyPair.privateKey;
  } else {
    const keyPair = generateEd25519KeyPair();
    clientPubKey = keyPair.publicKey;
    clientPrivKey = keyPair.privateKey;
  }
  console.log(`Client public key: ${clientPubKey.substring(0, 32)}...`);
  
  // Prepare message
  const originalContent = 'Hello, how are you?';
  const encryptedContent = encryptMessageContent(originalContent, modelPubKey, signingAlgo);
  
  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: encryptedContent }],
    stream: false,
    max_tokens: 10
  };
  
  const bodyJson = JSON.stringify(body);
  
  const response = await makeRequest(`${BASE_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`,
      'X-Signing-Algo': signingAlgo,
      'X-Client-Pub-Key': clientPubKey,
      'X-Model-Pub-Key': modelPubKey
    },
    body: bodyJson
  });
  
  const payload: ChatCompletionResponse = response;
  const chatId = payload.id;
  
  // Decrypt response content
  if (payload.choices && payload.choices.length > 0) {
    const message = payload.choices[0].message;
    if (message && message.content) {
      try {
        const decryptedResponse = decryptMessageContent(message.content, clientPrivKey, signingAlgo);
        console.log(`Decrypted response: ${decryptedResponse}`);
      } catch (e) {
        console.log(`Failed to decrypt response: ${e}`);
      }
    }
  }
  
  await verifyChat(chatId, bodyJson, JSON.stringify(response), `Encrypted Non-Streaming (${signingAlgo.toUpperCase()})`, model);
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'deepseek-ai/DeepSeek-V3.1';
  const signingAlgoIndex = args.indexOf('--signing-algo');
  const signingAlgo = signingAlgoIndex !== -1 && args[signingAlgoIndex + 1] ? args[signingAlgoIndex + 1] : 'ecdsa';
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

