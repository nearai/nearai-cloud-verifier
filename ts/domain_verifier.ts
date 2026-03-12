/**
 * Domain verifier — gateway TLS verification is the default behavior.
 *
 * Fetches attestation report with include_tls, verifies gateway report_data
 * binds tls_certificate, then compares that PEM's leaf cert to domain:443.
 */

import {
  AttestationReport,
  fetchReport,
  verifyAttestation,
} from "./model_verifier";
import { createHash, randomBytes, X509Certificate } from "crypto";
import * as tls from "tls";

const API_BASE: string = process.env.BASE_URL || "https://cloud-api.near.ai";

function parseCertificateChain(certChainPem: string): X509Certificate[] {
  const pemCertificateRegex =
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const parsedCertificates: X509Certificate[] = [];
  for (const certificateMatch of certChainPem.matchAll(pemCertificateRegex)) {
    try {
      parsedCertificates.push(new X509Certificate(certificateMatch[0]));
    } catch (parseError) {
      console.error("Failed to parse certificate from PEM:", parseError);
    }
  }
  return parsedCertificates;
}

/** SHA256(DER) fingerprint, OpenSSL-style colon-separated uppercase hex */
function getCertificateFingerprint(cert: X509Certificate): string {
  const hash = createHash("sha256").update(cert.raw).digest("hex");
  return hash.toUpperCase().match(/.{2}/g)?.join(":") || "";
}

/** TLS connect to domain:port and return leaf as X509Certificate */
function fetchLiveCertificate(
  domain: string,
  port: number = 443,
): Promise<X509Certificate> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(port, domain, {
      servername: domain,
      rejectUnauthorized: false,
    });
    let resolved = false;
    socket.on("secureConnect", () => {
      if (resolved) return;
      resolved = true;
      try {
        const cert = socket.getPeerX509Certificate();
        if (!cert) {
          socket.end();
          reject(new Error("Failed to get certificate from server"));
          return;
        }
        socket.end();
        const base64 = cert.raw.toString("base64");
        const base64Lines = base64.match(/.{1,64}/g);
        if (!base64Lines) {
          reject(new Error("Failed to encode certificate in PEM format"));
          return;
        }
        const pem =
          "-----BEGIN CERTIFICATE-----\n" +
          base64Lines.join("\n") +
          "\n-----END CERTIFICATE-----";
        resolve(new X509Certificate(pem));
      } catch (error) {
        socket.end();
        reject(
          new Error(
            `Failed to parse certificate from server: ${error instanceof Error ? error.message : "Unknown error"}`,
          ),
        );
      }
    });
    socket.on("error", (error) => {
      if (resolved) return;
      resolved = true;
      reject(new Error(`TLS connection failed: ${error.message}`));
    });
    socket.setTimeout(10000, () => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      reject(new Error("TLS connection timeout"));
    });
  });
}

/**
 * Compare leaf cert in attested PEM to live server cert (SHA256 DER fingerprint).
 */
async function compareCertificateFingerprints(
  domain: string,
  attestedPem: string,
): Promise<boolean> {
  const chain = parseCertificateChain(attestedPem);
  const evidenceLeaf = chain[0];
  if (!evidenceLeaf) {
    throw new Error("Failed to parse attested PEM (no certificate found)");
  }
  const evidenceFp = getCertificateFingerprint(evidenceLeaf);
  console.log(`Fetching certificate from live server: ${domain}:443`);
  const liveCert = await fetchLiveCertificate(domain, 443);
  const liveFp = getCertificateFingerprint(liveCert);
  const matches = evidenceFp === liveFp;
  console.log(`Fingerprints match: ${matches}`);
  if (!matches) {
    console.log("⚠️  Certificate fingerprint mismatch!");
    console.log(
      "   The certificate served by the live server does not match the attested tls_certificate.",
    );
    console.log(`   Attested PEM leaf fingerprint (SHA256): ${evidenceFp}`);
    console.log(`   Live server certificate fingerprint (SHA256): ${liveFp}`);
  }
  return matches;
}

function parseArgs(): {
  domain: string;
  signingAddress: string | undefined;
  model: string;
} {
  const argv = process.argv.slice(2);
  const domainFromEnv = process.env.DOMAIN;
  let domainFromUrl = "";
  try {
    domainFromUrl = new URL(API_BASE).hostname || "";
  } catch {
    // BASE_URL may be a bare hostname without scheme; use as domain candidate
    domainFromUrl = API_BASE.replace(/^https?:\/\//i, "").split("/")[0] || "";
  }
  let domain = domainFromEnv || domainFromUrl;

  const domainIdx = argv.indexOf("--domain");
  if (domainIdx !== -1 && argv[domainIdx + 1]) domain = argv[domainIdx + 1];

  let signingAddress: string | undefined =
    process.env.GATEWAY_SIGNING_ADDRESS || undefined;
  const addrIdx = argv.indexOf("--signing-address");
  if (addrIdx !== -1 && argv[addrIdx + 1]) signingAddress = argv[addrIdx + 1];

  let model = "deepseek-ai/DeepSeek-V3.1";
  const modelIdx = argv.indexOf("--model");
  if (modelIdx !== -1 && argv[modelIdx + 1]) model = argv[modelIdx + 1];

  return { domain, signingAddress, model };
}

/**
 * Fetch include_tls report, verify gateway attestation binds tls_certificate,
 * then ensure live :443 presents the same leaf cert.
 */
async function verifyDomainTlsViaAttestationReport(): Promise<void> {
  const { domain, signingAddress, model } = parseArgs();

  if (!domain) {
    console.error("DOMAIN, --domain, or BASE_URL with hostname is required.");
    process.exit(1);
  }

  console.log("========================================");
  console.log("🔐 Domain TLS vs attestation report");
  console.log("========================================");
  console.log("Domain:", domain);
  if (signingAddress) console.log("Signing address:", signingAddress);

  const nonce = randomBytes(32).toString("hex");
  const report = await fetchReport(
    model,
    nonce,
    "ecdsa",
    true,
    signingAddress,
  );

  const tlsPem = report.tls_certificate;
  if (!tlsPem || typeof tlsPem !== "string") {
    console.error(
      "No tls_certificate in attestation report. Set INGRESS_TLS_CERT_PATH on cloud-api and request include_tls.",
    );
    process.exit(1);
  }

  const gateway = report.gateway_attestation as AttestationReport | undefined;
  if (gateway) {
    console.log("\n🔐 Gateway attestation (include_tls binding)");
    await verifyAttestation(gateway, nonce, false, tlsPem);
  } else {
    console.log(
      "\n⚠️  No gateway_attestation in report; skipping TDX/report_data check. Still comparing TLS PEM to live.",
    );
  }

  console.log("\n🔐 Live TLS certificate vs attested tls_certificate");
  const ok = await compareCertificateFingerprints(domain, tlsPem);
  if (!ok) process.exit(1);
}

async function main(): Promise<void> {
  await verifyDomainTlsViaAttestationReport();
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export {
  compareCertificateFingerprints,
  fetchLiveCertificate,
  getCertificateFingerprint,
  parseCertificateChain,
  verifyDomainTlsViaAttestationReport,
};
