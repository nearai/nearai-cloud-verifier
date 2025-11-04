import { AttestationBaseInfo, checkTdxQuote, IntelResult, showCompose, showSigstoreProvenance } from "./model_verifier";
import { createHash, X509Certificate } from 'node:crypto'
import { Buffer } from 'buffer';
import * as tls from 'node:tls';

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
 * Gets the SHA256 fingerprint of a certificate in OpenSSL format
 * (colon-separated hex, uppercase)
 */
function getCertificateFingerprint(cert: X509Certificate): string {
  // Get the raw DER encoding of the certificate
  const der = cert.raw;
  // Compute SHA256 hash
  const hash = createHash('sha256').update(der).digest('hex');
  // Format as colon-separated uppercase hex (OpenSSL format)
  return hash.toUpperCase().match(/.{2}/g)?.join(':') || '';
}

/**
 * Fetches the certificate from a live server via TLS connection
 */
async function fetchLiveCertificate(domain: string, port: number = 443): Promise<X509Certificate> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, domain, {
      servername: domain,
      rejectUnauthorized: false, // We're just fetching the cert, not verifying it
    });

    let resolved = false;

    socket.on('secureConnect', () => {
      if (resolved) return;
      resolved = true;

      try {
        // Get the peer certificate (leaf certificate)
        const cert = socket.getPeerCertificate(false); // false = just the peer cert
        
        if (!cert) {
          socket.end();
          reject(new Error('Failed to get certificate from server'));
          return;
        }

        socket.end();

        // The cert object from Node.js TLS can be converted to PEM string
        // Convert certificate object to PEM string
        let pem: string;
        if (typeof cert === 'string') {
          pem = cert;
        } else if ((cert as any).raw) {
          // If raw Buffer is available, convert DER to PEM
          const raw = (cert as any).raw as Buffer;
          pem = '-----BEGIN CERTIFICATE-----\n' +
            raw.toString('base64').match(/.{1,64}/g)?.join('\n') +
            '\n-----END CERTIFICATE-----';
        } else {
          throw new Error('Certificate object format not recognized');
        }

        // Ensure PEM format is correct
        if (!pem.includes('BEGIN CERTIFICATE')) {
          throw new Error('Certificate is not in PEM format');
        }
        
        const x509Cert = new X509Certificate(pem);
        resolve(x509Cert);
      } catch (error) {
        socket.end();
        reject(new Error(`Failed to parse certificate from server: ${error instanceof Error ? error.message : 'Unknown error'}`));
      }
    });

    socket.on('error', (error) => {
      if (resolved) return;
      resolved = true;
      reject(new Error(`TLS connection failed: ${error.message}`));
    });

    socket.setTimeout(10000, () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      reject(new Error('TLS connection timeout'));
    });
  });
}

/**
 * Compares the certificate fingerprint from live server with evidence certificate
 */
async function compareCertificateFingerprints(domain: string, evidenceCertPem: string): Promise<boolean> {
  try {
    // Get fingerprint from evidence certificate
    const evidenceCertChain = parseCertificateChain(evidenceCertPem);
    const evidenceLeafCert = evidenceCertChain[0];
    if (!evidenceLeafCert) {
      throw new Error('Failed to parse evidence certificate');
    }
    const evidenceFingerprint = getCertificateFingerprint(evidenceLeafCert);

    // Get fingerprint from live server
    console.log(`Fetching certificate from live server: ${domain}:443`);
    const liveCert = await fetchLiveCertificate(domain, 443);
    const liveFingerprint = getCertificateFingerprint(liveCert);

    // Compare fingerprints    
    const matches = evidenceFingerprint === liveFingerprint;
    console.log(`Fingerprints match: ${matches}`);

    if (!matches) {
      console.log('⚠️  Certificate fingerprint mismatch!');
      console.log('   The certificate served by the live server does not match the evidence certificate.');
      console.log(`   Evidence certificate fingerprint (SHA256): ${evidenceFingerprint}`);
      console.log(`   Live server certificate fingerprint (SHA256): ${liveFingerprint}`);
    }

    return matches;
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    console.error('Certificate fingerprint comparison failed:', errorMessage);
    throw new Error(`Certificate fingerprint comparison failed: ${errorMessage}`);
  }
}

/**
 * Verifies certificate chain integrity and trust.
 */
export function verifyCertificateKey(certificate: string): boolean {
  try {
    const certificateChain = parseCertificateChain(certificate)
    const leafCertificate = certificateChain[0]

    if (!leafCertificate) {
      throw new Error(
        'Certificate verification failed: Unable to parse leaf certificate from certificate chain',
      )
    }

    // Verify certificate chain integrity
    if (!verifyCertificateChain(certificateChain)) {
      throw new Error(
        'Certificate verification failed: Certificate chain validation failed',
      )
    }

    // Verify root certificate trust
    const rootCertificate = certificateChain[certificateChain.length - 1]
    if (
      certificateChain.length > 1 &&
      rootCertificate &&
      !isRootCertificateTrusted(rootCertificate)
    ) {
      throw new Error(
        `Certificate verification failed: Root certificate is not trusted (issuer: ${rootCertificate.issuer})`,
      )
    }

    // Check certificate validity period
    const currentTime = new Date()
    if (new Date(leafCertificate.validFrom) > currentTime) {
      throw new Error(
        `Certificate verification failed: Certificate is not yet valid (valid from: ${leafCertificate.validFrom})`,
      )
    }

    if (new Date(leafCertificate.validTo) < currentTime) {
      throw new Error(
        `Certificate verification failed: Certificate has expired (valid to: ${leafCertificate.validTo})`,
      )
    }

    // Validate public keys
    const leafCertificatePublicKey = leafCertificate.publicKey.export({
      type: 'spki',
      format: 'der',
    })
    if (!leafCertificatePublicKey) {
      throw new Error(
        'Certificate verification failed: Unable to extract public key from certificate',
      )
    }
    console.log('Certificate public key:', leafCertificatePublicKey.toString('hex'));

    return true
  } catch (error) {
    const errorMessage =
      error instanceof Error
        ? error.message
        : 'Unknown certificate verification error'
    console.error('Certificate verification error:', errorMessage)
    throw new Error(`Certificate verification failed: ${errorMessage}`)
  }
}

async function checkCertificate(attestation: DomainAttestation) {
  console.log('\n🔐 SSL certificate');
  try {
    const certVerified = verifyCertificateKey(attestation.cert);
    console.log('Certificate verified:', certVerified);
    if (!certVerified) {
      console.log('Certificate verification failed');
    }
  } catch (error) {
    console.log('Certificate verified:', false);
    console.error('Certificate verification error:', error);
  }

  // Compare certificate fingerprint with live server
  try {
    await compareCertificateFingerprints(
      attestation.domain,
      attestation.cert
    );
  } catch (error) {
    console.error('Failed to compare certificate fingerprints:', error);
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

  // 4. Verify SSL certificate
  await checkCertificate(attestation);

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
  await verifyDomainAttestation(attestation);
}

// Run the main function if this file is executed directly
if (require.main === module) {
  main().catch(console.error);
}
