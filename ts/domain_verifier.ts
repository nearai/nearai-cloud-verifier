import { AttestationBaseInfo, checkTdxQuote, IntelResult, showCompose, showSigstoreProvenance } from "./model_verifier";
import { createHash, X509Certificate } from 'node:crypto'
import { Buffer } from 'buffer';

const API_BASE: string = process.env.BASE_URL || "https://cloud-api.near.ai";

interface DomainAttestation extends AttestationBaseInfo {
  domain: string;
  sha256sum: string;
  acmeAccount: string;
  cert: string;
}

interface ReportDataResult {
  sha256sum_matches: boolean;
  empty_bytes_matches: boolean;
}

/**
 * Verifies DNS CAA records for domain control.
 */
export async function verifyDnsCAA(
  domainName: string,
  acmeAccountUri: string,
): Promise<boolean> {
  const dnsUrl = `https://dns.google/resolve?name=${domainName}&type=CAA`
  try {
    const dnsResponse = await fetch(dnsUrl)

    if (!dnsResponse.ok) {
      throw new Error(
        `DNS CAA query failed for domain '${domainName}': ${dnsResponse.status} ${dnsResponse.statusText} (URL: ${dnsUrl})`,
      )
    }

    const { Answer: dnsRecords } = (await dnsResponse.json()) as {
      Answer?: Array<{ type: number; data?: string }>
    }

    const caaRecords = dnsRecords?.filter((record) => record.type === 257) ?? []

    if (caaRecords.length === 0) {
      throw new Error(
        `No CAA records found for domain '${domainName}' - domain does not have Certificate Authority Authorization configured`,
      )
    }

    const hasMatchingRecord = caaRecords.every((record) =>
      record.data?.includes(acmeAccountUri),
    )
    if (!hasMatchingRecord) {
      throw new Error(
        `CAA records for domain '${domainName}' do not authorize ACME account '${acmeAccountUri}' - found records: ${JSON.stringify(caaRecords.map((r) => r.data))}`,
      )
    }

    return true
  } catch (error) {
    const errorMessage =
      error instanceof Error
        ? error.message
        : `Unknown DNS CAA verification error for domain '${domainName}'`
    console.error('DNS CAA verification error:', errorMessage)
    throw new Error(`DNS CAA verification failed: ${errorMessage}`)
  }
}

// Helper functions

function parseCertificateChain(certChainPem: string): X509Certificate[] {
  const pemCertificateRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
  const parsedCertificates: X509Certificate[] = []

  for (const certificateMatch of certChainPem.matchAll(pemCertificateRegex)) {
    try {
      parsedCertificates.push(new X509Certificate(certificateMatch[0]))
    } catch (parseError) {
      console.error('Failed to parse certificate from PEM:', parseError)
    }
  }

  return parsedCertificates
}

function verifyCertificateChain(certificates: X509Certificate[]): boolean {
  if (certificates.length === 0) {
    throw new Error(
      'Certificate chain verification failed: Empty certificate chain',
    )
  }

  for (let index = 0; index < certificates.length; index++) {
    if (index === certificates.length - 1) continue // Skip root certificate

    const certificate = certificates[index]
    const issuerCertificate = certificates[index + 1]

    if (!certificate) {
      throw new Error(
        `Certificate chain verification failed: Missing certificate at index ${index}`,
      )
    }

    if (!issuerCertificate) {
      throw new Error(
        `Certificate chain verification failed: Missing issuer certificate for certificate ${index}`,
      )
    }

    try {
      const isVerified = certificate.verify(issuerCertificate.publicKey)
      const issuerMatches = certificate.issuer === issuerCertificate.subject

      if (!isVerified) {
        throw new Error(
          `Certificate chain verification failed: Certificate ${index} signature verification failed`,
        )
      }

      if (!issuerMatches) {
        throw new Error(
          `Certificate chain verification failed: Certificate ${index} issuer '${certificate.issuer}' does not match next certificate subject '${issuerCertificate.subject}'`,
        )
      }
    } catch (error) {
      const errorMessage =
        error instanceof Error
          ? error.message
          : `Unknown certificate chain verification error for certificate ${index}`
      console.error('Certificate chain verification error:', errorMessage)
      throw new Error(`Certificate chain verification failed: ${errorMessage}`)
    }
  }

  return true
}

function isRootCertificateTrusted(rootCertificate: X509Certificate): boolean {
  const trustedRootCaIssuers = [
    'C=US\nO=Internet Security Research Group\nCN=ISRG Root X1',
    'C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3',
  ]

  try {
    return rootCertificate.issuer === rootCertificate.subject
      ? rootCertificate.verify(rootCertificate.publicKey)
      : trustedRootCaIssuers.includes(rootCertificate.issuer)
  } catch (error) {
    const errorMessage =
      error instanceof Error
        ? error.message
        : 'Unknown root certificate trust verification error'
    console.error('Root certificate trust verification error:', errorMessage)
    throw new Error(
      `Root certificate trust verification failed: ${errorMessage}`,
    )
  }
}

/**
 * Verify that TDX report data binds the signing address and request nonce
 */
function checkReportData(attestation: DomainAttestation, intelResult: IntelResult): ReportDataResult {
  // Get expected report data from attestation
  const acmeAccountHash = createHash('sha256').update(attestation.acmeAccount).digest('hex');
  const certHash = createHash('sha256').update(attestation.cert).digest('hex');
  const expectedSha256sumFile = `${acmeAccountHash}  acme-account.json\n`
    + `${certHash}  cert-${attestation.domain}.pem\n`;
  const expectedSha256sum = createHash('sha256').update(expectedSha256sumFile).digest('hex');

  const reportDataHex = intelResult.quote.body.reportdata;
  const reportData = Buffer.from(reportDataHex.replace('0x', ''), 'hex');

  const embeddedSha256sum = reportData.subarray(0, 32).toString('hex');
  const emptyBytes = reportData.subarray(32).toString('hex');

  const sha256sumFileMatches = expectedSha256sumFile === attestation.sha256sum;
  const sha256sumMatches = embeddedSha256sum === expectedSha256sum;
  const emptyBytesMatches = emptyBytes === '0'.repeat(64);

  console.log('sha256sum.txt file matches:', sha256sumFileMatches);
  if (!sha256sumFileMatches) {
    console.log('sha256sum.txt file:', 'expected:', expectedSha256sumFile, 'actual:', attestation.sha256sum);
  }
  console.log('Report data binds sha256sum:', sha256sumMatches);
  if (!sha256sumMatches) {
    console.log('Report data sha256sum:', 'expected:', expectedSha256sum, 'actual:', embeddedSha256sum);
  }
  console.log('Report data embeds empty bytes:', emptyBytesMatches);
  if (!emptyBytesMatches) {
    console.log('Report data embeds empty bytes:', 'expected:', '0'.repeat(64), 'actual:', emptyBytes);
  }

  return {
    sha256sum_matches: sha256sumMatches,
    empty_bytes_matches: emptyBytesMatches
  };
}

/**
 * Verify domain attestation
 */
async function verifyDomainAttestation(attestation: DomainAttestation): Promise<void> {
  console.log('🔐 Attestation');

  if (!attestation.domain) {
    throw new Error(`Invalid domain: ${attestation.domain}`);
  }

  // 1. Verify Intel TDX quote
  console.log('\n🔐 Intel TDX quote');
  const intelResult = await checkTdxQuote(attestation);

  // 2. Check report data
  console.log('\n🔐 TDX report data');
  checkReportData(attestation, intelResult);

  // 3. Verify docker compose file
  showCompose(attestation, intelResult);
  await showSigstoreProvenance(attestation);

  // 4. Verify certificate


  // 5. Verify ACME account URI (optional)


}

/**
 * Fetch domain attestations from /evidences/ directory
 */
async function fetchDomainAttestation(): Promise<DomainAttestation> {
  const domain = API_BASE.split('/').pop();
  const evidencesUrl = `${API_BASE}/evidences/`;

  const sha256sumUrl = `${evidencesUrl}sha256sum.txt`;
  const acmeAccountUrl = `${evidencesUrl}acme-account.json`;
  const certUrl = `${evidencesUrl}cert-${domain}.pem`;
  const intelQuoteUrl = `${evidencesUrl}quote.json`;
  const infoUrl = `${evidencesUrl}info.json`;

  const [
    sha256sumResponse,
    acmeAccountResponse,
    certResponse,
    intelQuoteResponse,
    infoResponse,
  ] = await Promise.all([
    fetch(sha256sumUrl),
    fetch(acmeAccountUrl),
    fetch(certUrl),
    fetch(intelQuoteUrl),
    fetch(infoUrl),
  ]);

  const intelQuote = (await intelQuoteResponse.json()).quote;

  return {
    domain: domain ?? "",
    sha256sum: await sha256sumResponse.text(),
    acmeAccount: await acmeAccountResponse.text(),
    cert: await certResponse.text(),
    intel_quote: intelQuote,
    info: await infoResponse.json(),
  };
}

/**
 * Main verification function
 */
async function main(): Promise<void> {
  console.log('========================================');
  console.log('🔐 Domain Attestation');
  console.log('========================================');

  const attestation = await fetchDomainAttestation();

  console.log('Domain attestation:', JSON.stringify(attestation, null, 2));

  await verifyDomainAttestation(attestation);
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}
