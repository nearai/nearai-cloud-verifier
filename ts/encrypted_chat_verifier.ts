#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud End-to-End Encryption Test
 * Test end-to-end encryption for chat completions.
 */

import { URL } from 'url';
import {
  verifyChat,
} from './chat_verifier';
import {
  decryptText,
  encryptText,
  fetchModelPublicKey as fetchModelPublicKeyUtil,
  generateEcdsaKeyPair,
  generateEd25519KeyPair,
  decryptEcdsa,
  decryptEd25519,
  encryptEcdsa,
  encryptEd25519,
  makeRequest,
  type SigningAlgo,
} from './encryption_utils';
import * as https from 'https';
import * as http from 'http';

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';
const MAX_TOKENS = 100;

async function fetchModelPublicKey(model: string, signingAlgo: SigningAlgo = 'ecdsa'): Promise<string> {
  return await fetchModelPublicKeyUtil(BASE_URL, API_KEY, model, signingAlgo);
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

function encryptMessageContent(messageContent: string, modelPublicKey: string, signingAlgo: SigningAlgo): string {
  return encryptText(messageContent, modelPublicKey, signingAlgo);
}

function decryptMessageContent(encryptedHex: string, clientPrivateKey: any, signingAlgo: SigningAlgo): string {
  return decryptText(encryptedHex, clientPrivateKey, signingAlgo);
}

/**
 * Encrypted streaming example
 */
async function encryptedStreamingExample(model: string, signingAlgo: SigningAlgo = 'ecdsa'): Promise<void> {
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
      let responseText = '';
      let chatId: string | null = null;
      let decryptedContent = '';

      console.log(`✓ Request sent successfully (HTTP ${res.statusCode || 200})`);
      console.log('\nReceiving stream...');

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
                console.log(`✓ Chat ID: ${chatId}`);
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
                    process.stdout.write(`  Decrypted chunk: ${decryptedChunk}\n`);
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
          console.log(`✗ Failed to extract chat ID from streaming response`);
          reject(new Error('Failed to extract chat ID from streaming response'));
          return;
        }
        console.log(`\n\n✓ Complete decrypted response: ${decryptedContent}`);
        console.log(`✓ Total response length: ${responseText.length} bytes`);
        try {
          await verifyChat(chatId, bodyJson, responseText, `Encrypted Streaming (${signingAlgo.toUpperCase()})`, model);
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
async function encryptedNonStreamingExample(model: string, signingAlgo: SigningAlgo = 'ecdsa'): Promise<void> {
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
  try {
    response = await makeRequest(`${BASE_URL}/v1/chat/completions`, {
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
              console.log(`✗ Failed to decrypt ${field}: ${error}`);
              console.log(`  Encrypted ${field} (first 100 chars): ${fieldValue.substring(0, 100)}`);
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
  const signingAlgo = (signingAlgoIndex !== -1 && args[signingAlgoIndex + 1] ? args[signingAlgoIndex + 1] : 'ecdsa') as SigningAlgo;
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

