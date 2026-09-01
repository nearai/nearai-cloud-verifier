#!/usr/bin/env python3
"""Verify direct Compose Manager attestation evidence.

Compose Manager's nested quote binds ``SHA256(canonical actions JSON) || nonce``.
Recorded compose actions can also pin a file in ``nearai/cvm-compose-files`` by
commit and SHA-256. This is evidence of recorded deployment actions, not proof
that a particular model is currently running a compose file: the action log has
no model identity or successful-operation outcome.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote, urljoin, urlsplit

import requests

from py.utils.attestation import check_event_log, decode_hex, verify_dstack_quote


@dataclass(frozen=True)
class ComposeFileRecord:
    action_index: int
    commit: str
    file: str
    file_sha256: str


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_object(value: object, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def canonical_actions_json(actions: list[Any]) -> str:
    """Match Compose Manager's documented compact, sorted UTF-8 JSON contract."""

    return json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compose_manager_actions_hash(actions: list[Any]) -> str:
    return sha256(canonical_actions_json(actions).encode("utf-8")).hexdigest()


def direct_report_url(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be an absolute http:// or https:// URL")
    return urljoin(endpoint.rstrip("/") + "/", "/v1/attestation/report")


def fetch_compose_manager_attestation(
    url: str,
    nonce: str,
    signing_algo: Optional[str],
    token: Optional[str],
) -> Dict[str, Any]:
    params = {"nonce": nonce}
    if signing_algo is not None:
        params["signing_algo"] = signing_algo
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = requests.get(direct_report_url(url), params=params, headers=headers, timeout=30)
    response.raise_for_status()
    envelope = require_object(response.json(), "direct attestation response")
    report = require_object(
        envelope.get("compose_manager_attestation"),
        "direct attestation response.compose_manager_attestation",
    )
    if not isinstance(report.get("actions"), list):
        raise ValueError("compose_manager_attestation.actions must be an array")
    if not isinstance(report.get("event_log"), (str, list)):
        raise ValueError("compose_manager_attestation.event_log must be a JSON array or string")
    for name in ("actions_hash", "nonce", "quote", "report_data"):
        require_string(report.get(name), f"compose_manager_attestation.{name}")
    return report


def compose_file_records(actions: list[Any]) -> list[ComposeFileRecord]:
    records: list[ComposeFileRecord] = []
    for index, raw_action in enumerate(actions):
        action = require_object(raw_action, f"actions[{index}]")
        if not isinstance(action.get("file_sha256"), str):
            continue
        records.append(
            ComposeFileRecord(
                action_index=index,
                commit=require_string(action.get("commit"), f"actions[{index}].commit"),
                file=require_string(action.get("file"), f"actions[{index}].file"),
                file_sha256=require_string(
                    action.get("file_sha256"), f"actions[{index}].file_sha256"
                ),
            )
        )
    return records


def unique_compose_file_records(records: Iterable[ComposeFileRecord]) -> list[ComposeFileRecord]:
    unique: Dict[tuple[str, str, str], ComposeFileRecord] = {}
    for record in records:
        unique[(record.commit, record.file, record.file_sha256)] = record
    if not unique:
        raise ValueError("Compose Manager action log has no hash-pinned compose files")
    return list(unique.values())


def compose_source_url(record: ComposeFileRecord) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{40}", record.commit) is None:
        raise ValueError(
            f"actions[{record.action_index}].commit must be a 40-character Git commit"
        )
    segments = record.file.split("/")
    if not segments or any(not segment or segment in {".", ".."} for segment in segments):
        raise ValueError(
            f"actions[{record.action_index}].file must be a repository-relative path"
        )
    path = "/".join(quote(segment, safe="") for segment in segments)
    return f"https://raw.githubusercontent.com/nearai/cvm-compose-files/{record.commit}/{path}"


def verify_compose_file(record: ComposeFileRecord) -> None:
    expected = decode_hex(
        record.file_sha256, f"actions[{record.action_index}].file_sha256"
    )
    if len(expected) != 32:
        raise ValueError(f"actions[{record.action_index}].file_sha256 must be 32 bytes")
    response = requests.get(compose_source_url(record), timeout=30)
    response.raise_for_status()
    actual = sha256(response.content).digest()
    matches = actual == expected
    print(
        f"Compose file SHA-256 matches ({record.file} @ {record.commit}):",
        matches,
    )
    if not matches:
        print("  expected:", expected.hex())
        print("  actual:  ", actual.hex())
        raise RuntimeError(
            f"Pinned compose file hash does not match {record.file} at {record.commit}"
        )


def show_compose_manager_image_lookup(actions: list[Any]) -> None:
    images = set()
    for index, raw_action in enumerate(actions):
        action = require_object(raw_action, f"actions[{index}]")
        if action.get("action") == "compose_manager_started" and isinstance(
            action.get("image"), str
        ):
            images.add(action["image"])
    if not images:
        return
    print("\nGitHub artifact-attestation lookup (diagnostic only):")
    for image in sorted(images):
        match = re.fullmatch(r"nearaidev/compose-manager@sha256:([0-9a-fA-F]{64})", image)
        if match:
            print(
                "  https://api.github.com/repos/nearai/compose-manager/attestations/sha256:"
                + match.group(1)
            )
        else:
            print("  Compose Manager reported image:", image)


async def verify_compose_manager_attestation(
    url: str,
    signing_algo: Optional[str] = None,
    token: Optional[str] = None,
) -> None:
    """Verify nested Compose Manager evidence and its pinned compose sources."""

    nonce = secrets.token_hex(32)
    print("Request nonce:", nonce)
    report = fetch_compose_manager_attestation(url, nonce, signing_algo, token)
    actions = report["actions"]
    if not isinstance(actions, list):
        raise RuntimeError("Compose Manager report did not contain an actions array")

    requested_nonce = decode_hex(nonce, "request nonce")
    reported_nonce = decode_hex(
        require_string(report.get("nonce"), "compose_manager_attestation.nonce"),
        "compose_manager_attestation.nonce",
    )
    nonce_matches = len(reported_nonce) == 32 and reported_nonce == requested_nonce
    print("Compose Manager nonce matches request:", nonce_matches)
    if not nonce_matches:
        raise RuntimeError(
            "compose_manager_attestation.nonce does not match the requested nonce"
        )
    if isinstance(report.get("nonce_source"), str):
        print("Compose Manager nonce source:", report["nonce_source"])

    computed_actions_hash = bytes.fromhex(compose_manager_actions_hash(actions))
    advertised_actions_hash = decode_hex(
        require_string(report.get("actions_hash"), "compose_manager_attestation.actions_hash"),
        "compose_manager_attestation.actions_hash",
    )
    actions_match = len(advertised_actions_hash) == 32 and (
        computed_actions_hash == advertised_actions_hash
    )
    print("Canonical actions SHA-256 matches actions_hash:", actions_match)
    if not actions_match:
        print("  expected:", advertised_actions_hash.hex())
        print("  actual:  ", computed_actions_hash.hex())
        raise RuntimeError("compose_manager_attestation.actions do not match actions_hash")

    quote_attestation = {
        "intel_quote": require_string(report.get("quote"), "compose_manager_attestation.quote"),
        "event_log": report["event_log"],
    }
    print("\n🔐 Compose Manager Intel TDX quote")
    intel_result = await verify_dstack_quote(quote_attestation)
    if intel_result is None or intel_result.get("verified") is not True:
        raise RuntimeError("Compose Manager Intel TDX quote did not verify")
    if intel_result.get("debug_enabled") is not False:
        raise RuntimeError("Compose Manager Intel TDX quote enables debug mode")

    quoted_report_data = decode_hex(
        intel_result["quote"]["body"]["reportdata"],
        "verified Compose Manager quote report_data",
    )
    advertised_report_data = decode_hex(
        require_string(report.get("report_data"), "compose_manager_attestation.report_data"),
        "compose_manager_attestation.report_data",
    )
    if len(quoted_report_data) != 64 or len(advertised_report_data) != 64:
        raise ValueError("Compose Manager report_data must be 64 bytes")
    report_data_matches_quote = quoted_report_data == advertised_report_data
    print("Advertised report_data matches verified quote:", report_data_matches_quote)
    if not report_data_matches_quote:
        raise RuntimeError(
            "compose_manager_attestation.report_data does not match the verified quote"
        )
    report_data_binding_matches = quoted_report_data == computed_actions_hash + requested_nonce
    print("Quote binds actions_hash + request nonce:", report_data_binding_matches)
    if not report_data_binding_matches:
        raise RuntimeError(
            "Compose Manager quote does not bind actions_hash and the requested nonce"
        )

    print("\n🔐 Compose Manager event log")
    event_log = check_event_log(quote_attestation, intel_result)
    if event_log.get("replay_matches") is not True:
        raise RuntimeError("Compose Manager event log does not replay to the verified quote")

    records = unique_compose_file_records(compose_file_records(actions))
    print(f"\n🔐 Hash-pinned compose files ({len(records)})")
    for record in records:
        verify_compose_file(record)
    show_compose_manager_image_lookup(actions)

    print(
        "\n✓ Compose Manager deployment-transparency evidence passed. "
        "This verifies recorded actions, not the current deployment state or an inference response."
    )


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify direct Compose Manager attestation evidence"
    )
    parser.add_argument(
        "--url",
        required=True,
        help=(
            "Direct model endpoint whose report contains compose_manager_attestation, "
            "e.g. https://your-model.completions.near.ai"
        ),
    )
    parser.add_argument(
        "--signing-algo",
        choices=["ecdsa", "ed25519"],
        help="Optional direct-report signing algorithm",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("API_KEY"),
        help="Bearer token for endpoints that require authentication (default: API_KEY)",
    )
    args = parser.parse_args()

    print("========================================")
    print("🔐 Direct Compose Manager attestation")
    print("========================================")
    print("Target:", args.url)
    await verify_compose_manager_attestation(
        args.url,
        signing_algo=args.signing_algo,
        token=args.token,
    )


if __name__ == "__main__":
    asyncio.run(main())
