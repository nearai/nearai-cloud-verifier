#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud Signature Verifier
 * Minimal guide for checking signed chat responses.
 */

import * as crypto from 'crypto';
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { ethers } from 'ethers';
import {
  checkReportData,
  checkGpu,
  checkTdxQuote,
  showSigstoreProvenance,
  AttestationReport
} from './model_verifier';

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';

interface SignaturePayload {
  text: string;
  signature: string;
  signing_address: string;
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
 * Calculate SHA256 hash of text
 */
function sha256Text(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Fetch signature for a chat completion
 */
async function fetchSignature(chatId: string, model: string, signingAlgo: string = 'ecdsa'): Promise<SignaturePayload> {
  const url = `${BASE_URL}/v1/signature/${chatId}?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`;
  const headers = { Authorization: `Bearer ${API_KEY}` };
  return await makeRequest(url, { headers });
}

/**
 * Recover Ethereum address from ECDSA signature
 */
function recoverSigner(text: string, signature: string): string {
  return ethers.utils.verifyMessage(text, signature);
}

/**
 * Fetch attestation for a specific signing address
 */
async function fetchAttestationFor(signingAddress: string, model: string): Promise<[AttestationReport, string]> {
  const nonce = crypto.randomBytes(32).toString('hex');
  const url = `${BASE_URL}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}&signing_address=${signingAddress}`;
  const report = await makeRequest(url);

  // Handle both single attestation and multi-node response formats
  let attestation: AttestationReport;
  if (report.all_attestations) {
    // Multi-node format: find the attestation matching the signing address
    attestation = report.all_attestations.find(
      (item: AttestationReport) => item.signing_address.toLowerCase() === signingAddress.toLowerCase()
    )!;
  } else {
    // Single attestation format: use the report directly
    attestation = report;
  }

  return [attestation, nonce];
}

/**
 * Verify attestation for a signing address
 */
async function checkAttestation(signingAddress: string, attestation: AttestationReport, nonce: string): Promise<void> {
  const intelResult = await checkTdxQuote(attestation);
  checkReportData(attestation, nonce, intelResult);
  await checkGpu(attestation, nonce);
  await showSigstoreProvenance(attestation);
}

/**
 * Verify a chat completion signature and attestation
 */
async function verifyChat(chatId: string, requestBody: string, responseText: string, label: string, model: string): Promise<void> {
  const requestHash = sha256Text(requestBody);
  const responseHash = sha256Text(responseText);

  console.log(`\n--- ${label} ---`);
  const signaturePayload = await fetchSignature(chatId, model);
  console.log(JSON.stringify(signaturePayload, null, 2));

  const hashedText = signaturePayload.text;
  const [requestHashServer, responseHashServer] = hashedText.split(':');
  console.log('Request hash matches:', requestHash === requestHashServer);
  console.log('Response hash matches:', responseHash === responseHashServer);

  const signature = signaturePayload.signature;
  const signingAddress = signaturePayload.signing_address;
  const recovered = recoverSigner(hashedText, signature);
  console.log('Signature valid:', recovered.toLowerCase() === signingAddress.toLowerCase());

  const [attestation, nonce] = await fetchAttestationFor(signingAddress, model);
  console.log('\nAttestation signer:', attestation.signing_address);
  console.log('Attestation nonce:', nonce);
  await checkAttestation(signingAddress, attestation, nonce);
}

/**
 * Streaming example
 */
async function streamingExample(model: string): Promise<void> {
  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: 'Hello, how are you?' }],
    stream: true,
    max_tokens: 1
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
        'Authorization': `Bearer ${API_KEY}`
      },
      timeout: 30000
    };

    const req = client.request(requestOptions, (res) => {
      let responseText = '';
      let chatId: string | null = null;
      
      res.on('data', (chunk) => {
        const line = chunk.toString();
        responseText += line + '\n';
        
        if (line.startsWith('data: {') && chatId === null) {
          try {
            const data = JSON.parse(line.substring(6));
            chatId = data.id;
          } catch (error) {
            // Ignore parsing errors for non-JSON lines
          }
        }
      });
      
      res.on('end', async () => {
        if (chatId) {
          await verifyChat(chatId, bodyJson, responseText, 'Streaming example', model);
        }
        resolve();
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
 * Non-streaming example
 */
async function nonStreamingExample(model: string): Promise<void> {
  const body: ChatCompletionRequest = {
    model,
    messages: [{ role: 'user', content: 'Hello, how are you?' }],
    stream: false,
    max_tokens: 1
  };
  
  const bodyJson = JSON.stringify(body);
  const response = await makeRequest(`${BASE_URL}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${API_KEY}`
    },
    body: bodyJson
  });

  const payload: ChatCompletionResponse = response;
  const chatId = payload.id;
  await verifyChat(chatId, bodyJson, JSON.stringify(response), 'Non-streaming example', model);
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'deepseek-ai/DeepSeek-V3.1';

  if (!API_KEY) {
    console.log('Error: API_KEY environment variable is required');
    console.log('Set it with: export API_KEY=your-api-key');
    return;
  }

  await streamingExample(model);
  await nonStreamingExample(model);
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}

export {
  fetchSignature,
  recoverSigner,
  fetchAttestationFor,
  checkAttestation,
  verifyChat,
  streamingExample,
  nonStreamingExample,
  SignaturePayload,
  ChatCompletionRequest,
  ChatCompletionResponse
};
