#!/usr/bin/env python3
"""Inspect the deployed Gateway image provenance.

Fetches the Gateway attestation report, extracts the Docker image digest from
its attested compose file, then queries GitHub's attestations API to find the
exact git commit and build run. This is a release-provenance diagnostic, not a
TEE verification step.
"""

import base64
import json
import os
import re
import subprocess
import sys
import urllib.request

BASE_URL = os.environ.get("BASE_URL", "https://cloud-api.near.ai").rstrip("/")


def fetch_gateway_attestation() -> dict:
    """Fetch a Gateway attestation report using the configured API key."""
    api_base = BASE_URL if BASE_URL.endswith("/v1") else f"{BASE_URL}/v1"
    request = urllib.request.Request(
        f"{api_base}/attestation/report?signing_algo=ecdsa"
    )
    api_key = os.environ.get("API_KEY")
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    with urllib.request.urlopen(request) as resp:
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
    print(f"Fetching Gateway attestation from {BASE_URL}...")
    attestation = fetch_gateway_attestation()

    image_ref, digest_hex = extract_image_digest(attestation)
    print(f"\nImage:   {image_ref}")

    print("Querying GitHub attestations...")
    git_commit, build_url = fetch_provenance(digest_hex)

    print(f"Commit:  {git_commit}")
    print(f"Build:   {build_url}")
    print(f"GitHub:  https://github.com/nearai/cloud-api/commit/{git_commit}")


if __name__ == "__main__":
    main()
