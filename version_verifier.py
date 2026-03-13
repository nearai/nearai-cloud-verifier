#!/usr/bin/env python3
"""
Extract the deployed cloud-api version from its TDX attestation.

Fetches the attestation report from cloud-api.near.ai, extracts the Docker
image digest from the attested compose file, then queries GitHub's attestations
API to find the exact git commit and build run.
"""

import base64
import json
import re
import subprocess
import sys
import urllib.request

BASE_URL = "https://cloud-api.near.ai"


def fetch_attestation() -> dict:
    """Fetch attestation report from cloud-api."""
    with urllib.request.urlopen(f"{BASE_URL}/v1/attestation/report?signing_algo=ecdsa") as resp:
        return json.loads(resp.read())


def extract_image_digest(attestation: dict) -> tuple[str, str]:
    """Extract cloud-api image and sha256 digest from attested compose file.
    Returns (full_image_ref, digest_hex).
    """
    gateway = attestation["gateway_attestation"]
    app_compose = json.loads(gateway["info"]["tcb_info"]["app_compose"])
    compose_yaml = app_compose["docker_compose_file"]

    # Find nearaidev/cloud-api@sha256:... in the compose YAML
    match = re.search(r"(nearaidev/cloud-api@sha256:([0-9a-f]{64}))", compose_yaml)
    if not match:
        print("ERROR: Could not find cloud-api image in compose file", file=sys.stderr)
        sys.exit(1)

    return match.group(1), match.group(2)


def fetch_provenance(digest_hex: str) -> tuple[str, str]:
    """Query GitHub attestations API for the image digest.
    Returns (git_commit, build_url).
    """
    result = subprocess.run(
        ["gh", "api", f"repos/nearai/cloud-api/attestations/sha256:{digest_hex}"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(result.stdout)

    attestations = data.get("attestations", [])
    if not attestations:
        print("ERROR: No GitHub attestations found for this digest", file=sys.stderr)
        sys.exit(1)

    # Decode the DSSE payload from the first attestation
    payload_b64 = attestations[0]["bundle"]["dsseEnvelope"]["payload"]
    payload = json.loads(base64.b64decode(payload_b64))

    deps = payload["predicate"]["buildDefinition"]["resolvedDependencies"]
    git_commit = deps[0]["digest"]["gitCommit"]

    build_url = payload["predicate"]["runDetails"]["metadata"]["invocationId"]

    return git_commit, build_url


def main():
    print("Fetching attestation from cloud-api.near.ai...")
    attestation = fetch_attestation()

    image_ref, digest_hex = extract_image_digest(attestation)
    print(f"\nImage:   {image_ref}")

    print("Querying GitHub attestations...")
    git_commit, build_url = fetch_provenance(digest_hex)

    print(f"Commit:  {git_commit}")
    print(f"Build:   {build_url}")
    print(f"GitHub:  https://github.com/nearai/cloud-api/commit/{git_commit}")


if __name__ == "__main__":
    main()
