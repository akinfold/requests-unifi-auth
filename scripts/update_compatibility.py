#!/usr/bin/env python3
"""Upsert a pass row into COMPATIBILITY.md after a successful live e2e run."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPATIBILITY_PATH = REPO_ROOT / "COMPATIBILITY.md"
BADGE_PATH = REPO_ROOT / "badges" / "unifi-network.json"

HEADER = (
    "| Package | UniFi Network | UniFi OS | Date (UTC) | Result | Notes |\n"
    "|---|---|---|---|---|---|\n"
)

ROW_RE = re.compile(
    r"^\|\s*(?P<package>[^|]+?)\s*"
    r"\|\s*(?P<network>[^|]+?)\s*"
    r"\|\s*(?P<os>[^|]+?)\s*"
    r"\|\s*(?P<date>[^|]+?)\s*"
    r"\|\s*(?P<result>[^|]+?)\s*"
    r"\|\s*(?P<notes>[^|]*?)\s*"
    r"\|\s*$"
)


def _split_table(text: str) -> Tuple[str, List[str], str]:
    """Return (preamble, data_rows, postamble)."""
    lines = text.splitlines(keepends=True)
    start = None
    for index, line in enumerate(lines):
        if line.startswith("| Package |"):
            start = index
            break
    if start is None:
        return text if text.endswith("\n") or text == "" else text + "\n", [], ""

    # Skip header + separator
    data_start = start + 2
    data_rows: List[str] = []
    end = data_start
    while end < len(lines) and lines[end].startswith("|"):
        data_rows.append(lines[end].rstrip("\n"))
        end += 1

    preamble = "".join(lines[:start])
    postamble = "".join(lines[end:])
    return preamble, data_rows, postamble


def _format_row(
    package_version: str,
    network_version: str,
    os_version: str,
    date: str,
    result: str,
    notes: str,
) -> str:
    return (
        f"| {package_version} | {network_version} | {os_version} "
        f"| {date} | {result} | {notes} |"
    )


def _version_key(version: str) -> Optional[Tuple[int, ...]]:
    parts = version.strip().split(".")
    if not parts or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def latest_network_version(versions: Sequence[str]) -> Optional[str]:
    best: Optional[str] = None
    best_key: Optional[Tuple[int, ...]] = None
    for version in versions:
        key = _version_key(version)
        if key is None:
            continue
        if best_key is None or key > best_key:
            best_key = key
            best = version.strip()
    return best


def write_unifi_network_badge(
    network_version: str,
    *,
    path: Path = BADGE_PATH,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schemaVersion": 1,
        "label": "UniFi Network",
        "message": network_version,
        "color": "blue",
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def update_unifi_network_badge_from_matrix(
    *,
    compatibility_path: Path = COMPATIBILITY_PATH,
    badge_path: Path = BADGE_PATH,
) -> Optional[Path]:
    versions = list_tested_network_versions(compatibility_path)
    latest = latest_network_version(versions)
    if latest is None:
        return None
    return write_unifi_network_badge(latest, path=badge_path)


def update_compatibility_file(
    *,
    package_version: str,
    network_version: str,
    os_version: str = "unknown",
    result: str = "pass",
    notes: str = "live e2e",
    path: Path = COMPATIBILITY_PATH,
    badge_path: Path = BADGE_PATH,
    date: Optional[str] = None,
) -> Path:
    date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    network_version = network_version.strip() or "unknown"
    os_version = os_version.strip() or "unknown"
    package_version = package_version.strip()
    notes = notes.replace("|", "/").strip()

    if path.exists():
        text = path.read_text(encoding="utf-8")
    else:
        text = (
            "# Compatibility\n\n"
            "Live end-to-end results against real UniFi controllers. "
            "Updated automatically by `pytest -m e2e` on success; commit the change.\n\n"
        )

    preamble, rows, postamble = _split_table(text)
    if "| Package |" not in text:
        preamble = text.rstrip() + "\n\n"
        rows = []
        postamble = ""

    new_row = _format_row(
        package_version, network_version, os_version, date, result, notes
    )
    key = (package_version, network_version, os_version)
    updated = False
    new_rows: List[str] = []
    for row in rows:
        match = ROW_RE.match(row.strip())
        if not match:
            new_rows.append(row)
            continue
        row_key = (
            match.group("package").strip(),
            match.group("network").strip(),
            match.group("os").strip(),
        )
        if row_key == key:
            new_rows.append(new_row)
            updated = True
        else:
            new_rows.append(row)
    if not updated:
        new_rows.insert(0, new_row)

    body = preamble
    if not preamble.endswith("\n\n") and preamble and not preamble.endswith("\n"):
        body += "\n"
    body += HEADER
    body += "\n".join(new_rows) + "\n"
    if postamble:
        if not body.endswith("\n"):
            body += "\n"
        body += postamble if postamble.startswith("\n") else postamble

    path.write_text(body, encoding="utf-8")
    update_unifi_network_badge_from_matrix(
        compatibility_path=path, badge_path=badge_path
    )
    return path


def list_tested_network_versions(path: Path = COMPATIBILITY_PATH) -> List[str]:
    if not path.exists():
        return []
    versions: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        if match.group("result").strip().lower() != "pass":
            continue
        version = match.group("network").strip()
        if version and version != "unknown":
            versions.append(version)
    return versions


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-version", required=True)
    parser.add_argument("--network-version", required=True)
    parser.add_argument("--os-version", default="unknown")
    parser.add_argument("--notes", default="live e2e")
    parser.add_argument("--result", default="pass")
    args = parser.parse_args(argv)
    path = update_compatibility_file(
        package_version=args.package_version,
        network_version=args.network_version,
        os_version=args.os_version,
        result=args.result,
        notes=args.notes,
    )
    print(path)
    if BADGE_PATH.exists():
        print(BADGE_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
