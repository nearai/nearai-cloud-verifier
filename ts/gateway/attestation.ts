/**
 * Cloud API Gateway attestation flows.
 *
 * The Gateway and a model-serving TEE are distinct verification targets. A
 * verified Gateway attestation proves the Gateway deployment and the TLS peer
 * that returned the evidence. A verified model attestation proves a model
 * deployment and its optional GPU evidence. Neither one, by itself, refers to
 * a particular completion.
 */

import {
  type AttestationReport,
  hexBytesOfLength,
  verifyDstackDeployment,
  verifyDstackQuote,
  verifyNvidiaEvidence,
  verifyReportDataBinding,
  verifyReportDataBindingWithTlsFingerprint,
} from '../common/dstack_attestation';

export interface VerifyModelAttestationParams {
  attestation: AttestationReport;
  nonce: string;
}

export interface VerifiedModelAttestation {
  attestation: AttestationReport;
}

export interface VerifyGatewayAttestationParams {
  attestation: AttestationReport;
  nonce: string;
  peerSpkiFingerprint?: string;
}

export interface VerifiedGatewayAttestation {
  attestation: AttestationReport;
  peerSpkiFingerprint: string;
}

/**
 * Verify model-serving evidence returned by the Cloud API:
 * quote -> signer/nonce report-data binding -> measured deployment -> GPU.
 */
export async function verifyModelAttestation({
  attestation,
  nonce,
}: VerifyModelAttestationParams): Promise<VerifiedModelAttestation> {
  console.log('\n🔐 Model attestation');
  console.log('Signing address:', attestation.signing_address);
  console.log('Signing algorithm:', attestation.signing_algo);
  console.log('Request nonce:', nonce);

  console.log('\n🔐 Intel TDX quote');
  const quote = await verifyDstackQuote(attestation);

  console.log('\n🔐 Model report-data binding');
  verifyReportDataBinding({ attestation, requestNonce: nonce, intelResult: quote });

  await verifyDstackDeployment({ attestation, intelResult: quote });

  console.log('\n🔐 GPU evidence');
  await verifyNvidiaEvidence({ attestation, requestNonce: nonce });

  return { attestation };
}

/**
 * Verify Gateway evidence returned by the Cloud API:
 * quote -> signer/nonce/TLS report-data binding -> observed TLS peer ->
 * measured deployment.
 */
export async function verifyGatewayAttestation({
  attestation,
  nonce,
  peerSpkiFingerprint,
}: VerifyGatewayAttestationParams): Promise<VerifiedGatewayAttestation> {
  console.log('\n🔐 Gateway attestation');
  console.log('Signing address:', attestation.signing_address);
  console.log('Signing algorithm:', attestation.signing_algo);
  console.log('Request nonce:', nonce);

  console.log('\n🔐 Intel TDX quote');
  const quote = await verifyDstackQuote(attestation);

  console.log('\n🔐 Gateway report-data and TLS binding');
  const declaredTlsFingerprint = verifyReportDataBindingWithTlsFingerprint({
    attestation,
    requestNonce: nonce,
    intelResult: quote,
  });
  if (!peerSpkiFingerprint) {
    throw new Error(
      'Gateway verification needs the TLS peer fingerprint observed while fetching its attestation',
    );
  }
  const declared = hexBytesOfLength(
    declaredTlsFingerprint,
    32,
    'gateway_attestation.tls_cert_fingerprint',
  );
  const observed = hexBytesOfLength(
    peerSpkiFingerprint,
    32,
    'observed TLS peer SPKI fingerprint',
  );
  const matches = declared.equals(observed);
  console.log('Observed TLS peer SPKI matches attested fingerprint:', matches);
  if (!matches) {
    throw new Error('Observed TLS peer SPKI fingerprint does not match gateway attestation');
  }

  await verifyDstackDeployment({ attestation, intelResult: quote });

  return { attestation, peerSpkiFingerprint };
}
