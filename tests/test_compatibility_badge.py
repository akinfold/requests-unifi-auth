"""Tests for compatibility matrix and UniFi Network badge updates."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from update_compatibility import (  # noqa: E402
    latest_network_version,
    update_compatibility_file,
    write_unifi_network_badge,
)


def test_latest_network_version_picks_semver_max():
    assert latest_network_version(["9.0.0", "10.5.67", "10.4.100", "unknown"]) == "10.5.67"


def test_update_compatibility_writes_badge(tmp_path: Path):
    matrix = tmp_path / "COMPATIBILITY.md"
    badge = tmp_path / "badges" / "unifi-network.json"
    update_compatibility_file(
        package_version="0.1.4",
        network_version="10.5.67",
        os_version="unknown",
        path=matrix,
        badge_path=badge,
        date="2026-08-23",
    )
    update_compatibility_file(
        package_version="0.1.4",
        network_version="10.4.1",
        path=matrix,
        badge_path=badge,
        date="2026-08-20",
    )
    payload = json.loads(badge.read_text(encoding="utf-8"))
    assert payload["schemaVersion"] == 1
    assert payload["label"] == "UniFi Network"
    assert payload["message"] == "10.5.67"
    assert "10.5.67" in matrix.read_text(encoding="utf-8")


def test_write_unifi_network_badge_roundtrip(tmp_path: Path):
    path = write_unifi_network_badge("10.5.67", path=tmp_path / "unifi-network.json")
    assert json.loads(path.read_text(encoding="utf-8"))["message"] == "10.5.67"
