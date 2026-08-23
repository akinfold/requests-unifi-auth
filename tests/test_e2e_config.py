"""Unit tests for e2e config loading (no live controller)."""

from __future__ import annotations

import sys
from pathlib import Path

from pathlib import Path as _Path

# Import the loader without pulling in live e2e fixtures.
sys.path.insert(0, str(_Path(__file__).resolve().parent / "e2e"))
from config import load_e2e_settings, parse_dotenv  # noqa: E402


def test_parse_dotenv_ignores_comments_and_exports():
    text = """
# comment
export UNIFI_E2E_HOST=192.168.1.1
UNIFI_E2E_USERNAME="e2e-user"
UNIFI_E2E_PASSWORD='s3cret'
UNIFI_E2E_VERIFY_SSL=true
"""
    values = parse_dotenv(text)
    assert values["UNIFI_E2E_HOST"] == "192.168.1.1"
    assert values["UNIFI_E2E_USERNAME"] == "e2e-user"
    assert values["UNIFI_E2E_PASSWORD"] == "s3cret"
    assert values["UNIFI_E2E_VERIFY_SSL"] == "true"


def test_load_e2e_settings_from_file(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("UNIFI_E2E_HOST", raising=False)
    monkeypatch.delenv("UNIFI_E2E_USERNAME", raising=False)
    monkeypatch.delenv("UNIFI_E2E_PASSWORD", raising=False)
    monkeypatch.delenv("UNIFI_E2E_CONFIG", raising=False)

    config = tmp_path / "e2e.env"
    config.write_text(
        "UNIFI_E2E_HOST=ctrl.example\n"
        "UNIFI_E2E_USERNAME=user\n"
        "UNIFI_E2E_PASSWORD=pass\n"
        "UNIFI_E2E_SKIP_WRITE=true\n",
        encoding="utf-8",
    )
    config.chmod(0o600)

    loaded = load_e2e_settings(env={}, config_path=config)
    assert loaded is not None
    settings, password = loaded
    assert settings.host == "ctrl.example"
    assert settings.username == "user"
    assert password == "pass"
    assert settings.skip_write is True
    assert "password=***" in repr(settings)
    assert "password='pass'" not in repr(settings)
    assert 'password="pass"' not in repr(settings)


def test_env_overrides_file(tmp_path: Path):
    config = tmp_path / "e2e.env"
    config.write_text(
        "UNIFI_E2E_HOST=from-file\n"
        "UNIFI_E2E_USERNAME=file-user\n"
        "UNIFI_E2E_PASSWORD=file-pass\n",
        encoding="utf-8",
    )
    env = {
        "UNIFI_E2E_HOST": "from-env",
        "UNIFI_E2E_USERNAME": "file-user",
        "UNIFI_E2E_PASSWORD": "file-pass",
    }
    loaded = load_e2e_settings(env=env, config_path=config)
    assert loaded is not None
    settings, _password = loaded
    assert settings.host == "from-env"
