#!/usr/bin/env node
/**
 * TypeScript implementation of NEAR AI Cloud End-to-End Encryption Test for Image Generation
 * Test end-to-end encryption for image generation.
 */

import {
  verifyImage,
} from './image_verifier';
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

const API_KEY = process.env.API_KEY || '';
const BASE_URL = process.env.BASE_URL || 'https://cloud-api.near.ai';

async function fetchModelPublicKey(model: string, signingAlgo: SigningAlgo = 'ecdsa'): Promise<string> {
  return await fetchModelPublicKeyUtil(BASE_URL, API_KEY, model, signingAlgo);
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

function encryptPrompt(prompt: string, modelPublicKey: string, signingAlgo: SigningAlgo): string {
  return encryptText(prompt, modelPublicKey, signingAlgo);
}

function decryptPrompt(encryptedHex: string, clientPrivateKey: any, signingAlgo: SigningAlgo): string {
  return decryptText(encryptedHex, clientPrivateKey, signingAlgo);
}

/**
 * Encrypted image generation example
 */
async function encryptedImageGenerationExample(model: string, signingAlgo: SigningAlgo = 'ecdsa'): Promise<void> {
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
          } else {
            console.log(`⚠ b64_json for image ${i + 1} is not valid hex (might be plain base64): length=${encryptedB64.length}, isHex=${/^[0-9a-fA-F]+$/.test(encryptedB64)}`);
          }
        } else {
          console.log(`⚠ b64_json for image ${i + 1} is not valid. b64_json: ${encryptedB64}`);
        }
      } else {
        console.log(`⚠ b64_json for image ${i + 1} is not present`);
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
          } else {
            console.log(`⚠ revised_prompt for image ${i + 1} is not valid. revised_prompt: ${encryptedPrompt}`);
          }
        } else {
          console.log(`⚠ revised_prompt for image ${i + 1} is not valid. revised_prompt: ${encryptedPrompt}`);
        }
      } else {
        console.log(`⚠ revised_prompt for image ${i + 1} is not present`);
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
  const model = modelIndex !== -1 && args[modelIndex + 1] ? args[modelIndex + 1] : 'black-forest-labs/FLUX.2-klein-4B';
  const signingAlgoIndex = args.indexOf('--signing-algo');
  const signingAlgo = (signingAlgoIndex !== -1 && signingAlgoIndex + 1 < args.length && args[signingAlgoIndex + 1]
    ? args[signingAlgoIndex + 1]
    : 'ecdsa') as SigningAlgo;
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

