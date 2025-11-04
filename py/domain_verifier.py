#!/usr/bin/env python3
"""Python implementation of domain attestation verifier."""

import asyncio
import json
import os
import re
import socket
import ssl
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, List
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import SignatureAlgorithmOID

from model_verifier import (
    check_tdx_quote,
    show_compose,
    show_sigstore_provenance,
)

API_BASE = os.environ.get("BASE_URL", "https://cloud-api.near.ai")


class DomainAttestation:
    """Domain attestation data structure."""

    def __init__(
        self,
        domain: str,
        sha256sum: str,
        acme_account: str,
        cert: str,
        intel_quote: str,
        info: Dict,
    ):
        self.domain = domain
        self.sha256sum = sha256sum
        self.acme_account = acme_account
        self.cert = cert
        self.intel_quote = intel_quote
        self.info = info


class ReportDataResult:
    """Result of report data verification."""

    def __init__(self, sha256sum_matches: bool, empty_bytes_matches: bool):
        self.sha256sum_matches = sha256sum_matches
        self.empty_bytes_matches = empty_bytes_matches


async def verify_dns_caa(domain_name: str, acme_account_uri: str) -> bool:
    """Verify DNS CAA records for domain control."""
    dns_url = f"https://dns.google/resolve?name={domain_name}&type=CAA"
    try:
        dns_response = requests.get(dns_url, timeout=10)

        if not dns_response.ok:
            raise Exception(
                f"DNS CAA query failed for domain '{domain_name}': "
                f"{dns_response.status_code} {dns_response.reason} (URL: {dns_url})"
            )

        dns_data = dns_response.json()
        dns_records = dns_data.get("Answer", [])

        caa_records = [record for record in dns_records if record.get("type") == 257]

        if len(caa_records) == 0:
            raise Exception(
                f"No CAA records found for domain '{domain_name}' - "
                "domain does not have Certificate Authority Authorization configured"
            )

        has_matching_record = all(
            acme_account_uri in record.get("data", "") for record in caa_records
        )
        if not has_matching_record:
            raise Exception(
                f"CAA records for domain '{domain_name}' do not authorize "
                f"ACME account '{acme_account_uri}' - found records: "
                f"{json.dumps([r.get('data') for r in caa_records])}"
            )

        return True
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception) else f"Unknown DNS CAA verification error for domain '{domain_name}'"
        )
        print(f"DNS CAA verification error: {error_message}")
        raise Exception(f"DNS CAA verification failed: {error_message}")


def parse_certificate_chain(cert_chain_pem: str) -> List[x509.Certificate]:
    """Parse PEM certificate chain into list of X509 certificates."""
    pem_certificate_regex = r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"
    parsed_certificates = []

    for certificate_match in re.finditer(pem_certificate_regex, cert_chain_pem):
        try:
            cert_pem = certificate_match.group(0)
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode(), default_backend()
            )
            parsed_certificates.append(cert)
        except Exception as parse_error:
            print(f"Failed to parse certificate from PEM: {parse_error}")

    return parsed_certificates


def verify_certificate_chain(certificates: List[x509.Certificate]) -> bool:
    """Verify certificate chain integrity."""
    if len(certificates) == 0:
        raise Exception("Certificate chain verification failed: Empty certificate chain")

    for index in range(len(certificates) - 1):
        certificate = certificates[index]
        issuer_certificate = certificates[index + 1]

        if certificate is None:
            raise Exception(
                f"Certificate chain verification failed: Missing certificate at index {index}"
            )

        if issuer_certificate is None:
            raise Exception(
                f"Certificate chain verification failed: Missing issuer certificate for certificate {index}"
            )

        try:
            # Verify signature using issuer's public key
            issuer_public_key = issuer_certificate.public_key()
            signature_algorithm = certificate.signature_algorithm_oid

            # Determine hash algorithm from signature algorithm
            if signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA256:
                hash_algorithm = hashes.SHA256()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA384:
                hash_algorithm = hashes.SHA384()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA512:
                hash_algorithm = hashes.SHA512()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                hash_algorithm = hashes.SHA256()
                padding_algorithm = None
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA384:
                hash_algorithm = hashes.SHA384()
                padding_algorithm = None
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA512:
                hash_algorithm = hashes.SHA512()
                padding_algorithm = None
            else:
                # Default to SHA256
                hash_algorithm = hashes.SHA256()
                padding_algorithm = (
                    padding.PKCS1v15() if isinstance(issuer_public_key, rsa.RSAPublicKey) else None
                )

            # Verify signature
            try:
                if isinstance(issuer_public_key, rsa.RSAPublicKey):
                    issuer_public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        padding_algorithm,
                        hash_algorithm,
                    )
                elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                    issuer_public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        ec.ECDSA(hash_algorithm),
                    )
                else:
                    raise Exception("Unsupported public key type")
            except Exception as verify_error:
                raise Exception(
                    f"Certificate chain verification failed: Certificate {index} signature verification failed: {verify_error}"
                )

            # Verify issuer matches
            issuer_dn = certificate.issuer.rfc4514_string()
            subject_dn = issuer_certificate.subject.rfc4514_string()

            if issuer_dn != subject_dn:
                raise Exception(
                    f"Certificate chain verification failed: Certificate {index} issuer "
                    f"'{issuer_dn}' does not match next certificate subject '{subject_dn}'"
                )
        except Exception as error:
            error_message = (
                str(error) if isinstance(error, Exception)
                else f"Unknown certificate chain verification error for certificate {index}"
            )
            print(f"Certificate chain verification error: {error_message}")
            raise Exception(f"Certificate chain verification failed: {error_message}")

    return True


def _extract_dn_components(dn_string: str) -> Dict[str, str]:
    """Extract DN components for flexible comparison."""
    components = {}
    # RFC4514 format: "CN=...,O=...,C=..." or "C=US\nO=...\nCN=..."
    # Handle both comma-separated and newline-separated formats
    if "\n" in dn_string:
        parts = dn_string.split("\n")
    else:
        parts = dn_string.split(",")
    for part in parts:
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            components[key.strip()] = value.strip()
    return components


def is_root_certificate_trusted(root_certificate: x509.Certificate) -> bool:
    """Check if root certificate is trusted."""
    trusted_root_ca_issuers = [
        "C=US\nO=Internet Security Research Group\nCN=ISRG Root X1",
        "CN=ISRG Root X1,O=Internet Security Research Group,C=US",
        "C=US\nO=Digital Signature Trust Co.\nCN=DST Root CA X3",
        "CN=DST Root CA X3,O=Digital Signature Trust Co.,C=US",
    ]

    try:
        issuer_dn = root_certificate.issuer.rfc4514_string()
        subject_dn = root_certificate.subject.rfc4514_string()

        # Check if issuer is in trusted list (exact match or component match)
        issuer_in_trusted = issuer_dn in trusted_root_ca_issuers
        if not issuer_in_trusted:
            # Try component-based matching
            issuer_components = _extract_dn_components(issuer_dn)
            for trusted_issuer in trusted_root_ca_issuers:
                trusted_components = _extract_dn_components(trusted_issuer)
                if (
                    issuer_components.get("CN") == trusted_components.get("CN")
                    and issuer_components.get("O") == trusted_components.get("O")
                    and issuer_components.get("C") == trusted_components.get("C")
                ):
                    issuer_in_trusted = True
                    break

        if issuer_dn == subject_dn:
            # Self-signed root certificate - verify signature
            public_key = root_certificate.public_key()
            signature_algorithm = root_certificate.signature_algorithm_oid

            # Determine hash algorithm from signature algorithm
            if signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA256:
                hash_algorithm = hashes.SHA256()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA384:
                hash_algorithm = hashes.SHA384()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.RSA_WITH_SHA512:
                hash_algorithm = hashes.SHA512()
                padding_algorithm = padding.PKCS1v15()
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA256:
                hash_algorithm = hashes.SHA256()
                padding_algorithm = None
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA384:
                hash_algorithm = hashes.SHA384()
                padding_algorithm = None
            elif signature_algorithm == SignatureAlgorithmOID.ECDSA_WITH_SHA512:
                hash_algorithm = hashes.SHA512()
                padding_algorithm = None
            else:
                hash_algorithm = hashes.SHA256()
                padding_algorithm = (
                    padding.PKCS1v15() if isinstance(public_key, rsa.RSAPublicKey) else None
                )

            try:
                if isinstance(public_key, rsa.RSAPublicKey):
                    public_key.verify(
                        root_certificate.signature,
                        root_certificate.tbs_certificate_bytes,
                        padding_algorithm,
                        hash_algorithm,
                    )
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    public_key.verify(
                        root_certificate.signature,
                        root_certificate.tbs_certificate_bytes,
                        ec.ECDSA(hash_algorithm),
                    )
                return True
            except Exception:
                # If signature verification fails, still check if issuer is trusted
                return issuer_in_trusted
        else:
            return issuer_in_trusted
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception)
            else "Unknown root certificate trust verification error"
        )
        print(f"Root certificate trust verification error: {error_message}")
        raise Exception(f"Root certificate trust verification failed: {error_message}")


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get the SHA256 fingerprint of a certificate in OpenSSL format (colon-separated hex, uppercase)."""
    # Get the raw DER encoding of the certificate
    der = cert.public_bytes(encoding=serialization.Encoding.DER)
    # Compute SHA256 hash
    hash_obj = sha256(der)
    hash_hex = hash_obj.hexdigest().upper()
    # Format as colon-separated uppercase hex (OpenSSL format)
    return ":".join(hash_hex[i : i + 2] for i in range(0, len(hash_hex), 2))


async def fetch_live_certificate(domain: str, port: int = 443) -> x509.Certificate:
    """Fetch the certificate from a live server via TLS connection."""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Create socket and wrap with SSL (using asyncio.to_thread for blocking operations)
        def _fetch_cert():
            sock = socket.create_connection((domain, port), timeout=10)
            try:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get the peer certificate (leaf certificate)
                    cert_der = ssock.getpeercert(binary_form=True)

                    if not cert_der:
                        raise Exception("Failed to get certificate from server")

                    # Convert DER to X509 certificate
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    return cert
            finally:
                sock.close()

        # Run blocking socket operations in a thread
        cert = await asyncio.to_thread(_fetch_cert)
        return cert
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception) else "Unknown TLS connection error"
        )
        raise Exception(f"TLS connection failed: {error_message}")


async def compare_certificate_fingerprints(
    domain: str, evidence_cert_pem: str
) -> bool:
    """Compare the certificate fingerprint from live server with evidence certificate."""
    try:
        # Get fingerprint from evidence certificate
        evidence_cert_chain = parse_certificate_chain(evidence_cert_pem)
        if len(evidence_cert_chain) == 0:
            raise Exception("Failed to parse evidence certificate")
        evidence_leaf_cert = evidence_cert_chain[0]
        evidence_fingerprint = get_certificate_fingerprint(evidence_leaf_cert)

        # Get fingerprint from live server
        print(f"Fetching certificate from live server: {domain}:443")
        live_cert = await fetch_live_certificate(domain, 443)
        live_fingerprint = get_certificate_fingerprint(live_cert)

        # Compare fingerprints
        matches = evidence_fingerprint == live_fingerprint
        print(f"Fingerprints match: {matches}")

        if not matches:
            print("⚠️  Certificate fingerprint mismatch!")
            print(
                "   The certificate served by the live server does not match the evidence certificate."
            )
            print(f"   Evidence certificate fingerprint (SHA256): {evidence_fingerprint}")
            print(f"   Live server certificate fingerprint (SHA256): {live_fingerprint}")

        return matches
    except Exception as error:
        error_message = str(error) if isinstance(error, Exception) else "Unknown error"
        print(f"Certificate fingerprint comparison failed: {error_message}")
        raise Exception(f"Certificate fingerprint comparison failed: {error_message}")


def verify_certificate_key(certificate: str) -> bool:
    """Verify certificate chain integrity and trust."""
    try:
        certificate_chain = parse_certificate_chain(certificate)
        if len(certificate_chain) == 0:
            raise Exception(
                "Certificate verification failed: Unable to parse leaf certificate from certificate chain"
            )
        leaf_certificate = certificate_chain[0]

        # Verify certificate chain integrity
        if not verify_certificate_chain(certificate_chain):
            raise Exception(
                "Certificate verification failed: Certificate chain validation failed"
            )

        # Verify root certificate trust
        if len(certificate_chain) > 1:
            root_certificate = certificate_chain[-1]
            if root_certificate and not is_root_certificate_trusted(root_certificate):
                issuer_dn = root_certificate.issuer.rfc4514_string()
                raise Exception(
                    f"Certificate verification failed: Root certificate is not trusted (issuer: {issuer_dn})"
                )

        # Check certificate validity period
        current_time = datetime.now(timezone.utc)
        # Use UTC-aware datetime properties (timezone-aware)
        not_valid_before = leaf_certificate.not_valid_before_utc
        not_valid_after = leaf_certificate.not_valid_after_utc

        if not_valid_before > current_time:
            raise Exception(
                f"Certificate verification failed: Certificate is not yet valid "
                f"(valid from: {not_valid_before})"
            )

        if not_valid_after < current_time:
            raise Exception(
                f"Certificate verification failed: Certificate has expired "
                f"(valid to: {not_valid_after})"
            )

        # Validate public keys
        leaf_certificate_public_key = leaf_certificate.public_key()
        if not leaf_certificate_public_key:
            raise Exception(
                "Certificate verification failed: Unable to extract public key from certificate"
            )
        public_key_bytes = leaf_certificate_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        print("Certificate public key:", public_key_bytes.hex())

        return True
    except Exception as error:
        error_message = (
            str(error) if isinstance(error, Exception) else "Unknown certificate verification error"
        )
        print(f"Certificate verification error: {error_message}")
        raise Exception(f"Certificate verification failed: {error_message}")


async def check_certificate(attestation: DomainAttestation) -> None:
    """Check SSL certificate."""
    print("\n🔐 SSL certificate")
    try:
        cert_verified = verify_certificate_key(attestation.cert)
        print("Certificate verified:", cert_verified)
        if not cert_verified:
            print("Certificate verification failed")
    except Exception as error:
        print("Certificate verified:", False)
        print(f"Certificate verification error: {error}")

    # Compare certificate fingerprint with live server
    try:
        await compare_certificate_fingerprints(attestation.domain, attestation.cert)
    except Exception as error:
        print(f"Failed to compare certificate fingerprints: {error}")


async def check_dns_caa(attestation: DomainAttestation) -> None:
    """Check DNS CAA record."""
    print("\n🔐 DNS CAA record")
    try:
        acme_account_data = json.loads(attestation.acme_account)
        acme_account_uri = acme_account_data["uri"]
        verified = await verify_dns_caa(attestation.domain, acme_account_uri)
        print("DNS CAA verified:", verified)
    except Exception as error:
        print(f"Failed to verify DNS CAA: {error}")


def check_report_data(
    attestation: DomainAttestation, intel_result: Dict
) -> ReportDataResult:
    """Verify that the TDX report data binds the ACME account and certificate hashes (sha256sum)."""
    # Get expected report data from attestation
    acme_account_hash = sha256(attestation.acme_account.encode()).hexdigest()
    cert_hash = sha256(attestation.cert.encode()).hexdigest()
    expected_sha256sum_file = (
        f"{acme_account_hash}  acme-account.json\n"
        f"{cert_hash}  cert-{attestation.domain}.pem\n"
    )
    expected_sha256sum = sha256(expected_sha256sum_file.encode()).hexdigest()

    report_data_hex = intel_result["quote"]["body"]["reportdata"]
    report_data = bytes.fromhex(report_data_hex.replace("0x", ""))

    embedded_sha256sum = report_data[:32].hex()
    empty_bytes = report_data[32:].hex()

    sha256sum_file_matches = expected_sha256sum_file == attestation.sha256sum
    sha256sum_matches = embedded_sha256sum == expected_sha256sum
    empty_bytes_matches = empty_bytes == "0" * 64

    print("sha256sum.txt file matches:", sha256sum_file_matches)
    if not sha256sum_file_matches:
        print(
            "sha256sum.txt file:",
            "expected:",
            expected_sha256sum_file,
            "actual:",
            attestation.sha256sum,
        )
    print("Report data embeds sha256sum:", sha256sum_matches)
    if not sha256sum_matches:
        print(
            "Report data sha256sum:",
            "expected:",
            expected_sha256sum,
            "actual:",
            embedded_sha256sum,
        )
    print("Report data embeds empty bytes:", empty_bytes_matches)
    if not empty_bytes_matches:
        print(
            "Report data embeds empty bytes:",
            "expected:",
            "0" * 64,
            "actual:",
            empty_bytes,
        )

    return ReportDataResult(
        sha256sum_matches=sha256sum_matches, empty_bytes_matches=empty_bytes_matches
    )


async def verify_domain_attestation(attestation: DomainAttestation) -> None:
    """Verify domain attestation."""
    if not attestation.domain:
        raise Exception(f"Invalid domain: {attestation.domain}")

    # 1. Verify Intel TDX quote
    print("\n🔐 Intel TDX quote")
    # Convert attestation to dict format expected by check_tdx_quote
    attestation_dict = {
        "intel_quote": attestation.intel_quote,
        "info": attestation.info,
    }
    intel_result = await check_tdx_quote(attestation_dict)

    # 2. Check report data
    print("\n🔐 TDX report data")
    check_report_data(attestation, intel_result)

    # 3. Verify docker compose file
    show_compose(attestation_dict, intel_result)
    show_sigstore_provenance(attestation_dict)

    # 4. Verify SSL certificate
    await check_certificate(attestation)


async def fetch_domain_attestation() -> DomainAttestation:
    """Fetch domain attestations from /evidences/ directory."""
    domain = urlparse(API_BASE).hostname
    evidences_url = f"{API_BASE}/evidences/"

    sha256sum_url = f"{evidences_url}sha256sum.txt"
    acme_account_url = f"{evidences_url}acme-account.json"
    cert_url = f"{evidences_url}cert-{domain}.pem"
    intel_quote_url = f"{evidences_url}quote.json"
    info_url = f"{evidences_url}info.json"

    responses = await asyncio.gather(
        asyncio.to_thread(requests.get, sha256sum_url),
        asyncio.to_thread(requests.get, acme_account_url),
        asyncio.to_thread(requests.get, cert_url),
        asyncio.to_thread(requests.get, intel_quote_url),
        asyncio.to_thread(requests.get, info_url),
    )

    sha256sum_response, acme_account_response, cert_response, intel_quote_response, info_response = responses

    intel_quote = intel_quote_response.json()["quote"]

    return DomainAttestation(
        domain=domain or "",
        sha256sum=sha256sum_response.text,
        acme_account=acme_account_response.text,
        cert=cert_response.text,
        intel_quote=intel_quote,
        info=info_response.json(),
    )


async def main() -> None:
    """Main verification function."""
    print("========================================")
    print("🔐 Domain Attestation")
    print("========================================")

    attestation = await fetch_domain_attestation()
    await verify_domain_attestation(attestation)


if __name__ == "__main__":
    asyncio.run(main())

