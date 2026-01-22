#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud Image Generation Signature Verifier
 * Minimal guide for checking signed image generation responses.
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
        data += chunk;
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
 * Calculate SHA256 hash of text
 */
function sha256Text(text: string): string {
  return crypto.createHash('sha256').update(text).digest('hex');
}

/**
 * Fetch signature for an image generation
 */
async function fetchSignature(imageId: string, model: string, signingAlgo: string = 'ecdsa'): Promise<SignaturePayload> {
  const url = `${BASE_URL}/v1/signature/${imageId}?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`;
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
  const url = `${BASE_URL}/v1/attestation/report?model=${encodeURIComponent(model)}&nonce=${nonce}&signing_algo=ecdsa&signing_address=${signingAddress}`;
  const report = await makeRequest(url);

  // Handle both single attestation and multi-node response formats
  let attestation: AttestationReport;
  if (report.model_attestations) {
    // Multi-node format: find the attestation matching the signing address
    attestation = report.model_attestations.find(
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
 * Verify an image generation signature and attestation
 */
async function verifyImage(imageId: string, requestBody: string, responseText: string, label: string, model: string): Promise<void> {
  const requestHash = sha256Text(requestBody);
  const responseHash = sha256Text(responseText);

  console.log(`\n--- ${label} ---`);
  const signaturePayload = await fetchSignature(imageId, model);
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
  if (!attestation || "error" in attestation) {
    console.log(`Attestation not found for signing address: ${signingAddress}.`, attestation);
    return;
  }
  console.log('\nAttestation signer:', attestation.signing_address);
  console.log('Attestation nonce:', nonce);
  await checkAttestation(signingAddress, attestation, nonce);
}

/**
 * Image generation example
 */
async function imageGenerationExample(model: string): Promise<void> {
  const body: ImageGenerationRequest = {
    model,
    prompt: 'a beautiful sunset over mountains',
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
        'Authorization': `Bearer ${API_KEY}`
      },
      body: bodyJson,
      timeout: 60000 // Image generation may take longer
    });
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
  // The response from the provider includes an 'id' field
  const imageId = payload.id;
  if (!imageId) {
    console.log('Error: Response does not contain \'id\' field');
    console.log('Response:', JSON.stringify(payload, null, 2));
    return;
  }

  await verifyImage(imageId, bodyJson, JSON.stringify(response), 'Image generation example', model);
}

/**
 * Main function
 */
async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const modelIndex = args.indexOf('--model');
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'Qwen/Qwen-Image';

  if (!API_KEY) {
    console.log('Error: API_KEY environment variable is required');
    console.log('Set it with: export API_KEY=your-api-key');
    return;
  }

  await imageGenerationExample(model);
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
  verifyImage,
  imageGenerationExample,
  SignaturePayload,
  ImageGenerationRequest,
  ImageGenerationResponse
};

