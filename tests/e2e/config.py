"""Load live e2e settings from a dotenv file and/or environment variables."""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional


_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class E2ESettings:
    host: str
    username: str
    # Password is intentionally omitted from repr for pytest --showlocals safety
    verify_ssl: bool = False
    skip_write: bool = False
    config_path: Optional[Path] = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"E2ESettings(host={self.host!r}, username={self.username!r}, "
            f"password=***, verify_ssl={self.verify_ssl}, "
            f"skip_write={self.skip_write}, config_path={self.config_path!r})"
        )


def _xdg_config_home() -> Path:
    raw = os.environ.get("XDG_CONFIG_HOME", "").strip()
    if raw:
        return Path(raw)
    return Path.home() / ".config"


def candidate_config_paths() -> list[Path]:
    paths: list[Path] = []
    explicit = os.environ.get("UNIFI_E2E_CONFIG", "").strip()
    if explicit:
        paths.append(Path(explicit).expanduser())
    base = _xdg_config_home() / "requests-unifi-auth" / "e2e.env"
    if base not in paths:
        paths.append(base)
    return paths


def find_config_file() -> Optional[Path]:
    for path in candidate_config_paths():
        if path.is_file():
            return path
    return None


def parse_dotenv(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def load_dotenv_file(path: Path) -> Dict[str, str]:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        mode = 0
    if mode & 0o077:
        warnings.warn(
            f"e2e config {path} is readable by group/other (mode {mode:o}); "
            "prefer chmod 600",
            UserWarning,
            stacklevel=2,
        )
    return parse_dotenv(path.read_text(encoding="utf-8"))


def _flag(raw: Optional[str], default: bool = False) -> bool:
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in _TRUE


def _get(
    env: Mapping[str, str],
    file_values: Mapping[str, str],
    key: str,
) -> Optional[str]:
    if key in env and env[key] != "":
        return env[key]
    if key in file_values and file_values[key] != "":
        return file_values[key]
    return None


def load_e2e_settings(
    env: Optional[Mapping[str, str]] = None,
    *,
    config_path: Optional[Path] = None,
) -> Optional[tuple[E2ESettings, str]]:
    """Return (settings, password) or None if required fields are missing.

    Password is returned separately so fixtures can avoid storing it on
    objects that pytest may print via --showlocals.
    """
    env_map: Mapping[str, str] = os.environ if env is None else env
    path = config_path
    file_values: Dict[str, str] = {}
    if path is None:
        path = find_config_file()
    if path is not None and path.is_file():
        file_values = load_dotenv_file(path)

    host = (_get(env_map, file_values, "UNIFI_E2E_HOST") or "").strip()
    username = (_get(env_map, file_values, "UNIFI_E2E_USERNAME") or "").strip()
    password = _get(env_map, file_values, "UNIFI_E2E_PASSWORD") or ""
    if not host or not username or not password:
        return None

    settings = E2ESettings(
        host=host,
        username=username,
        verify_ssl=_flag(_get(env_map, file_values, "UNIFI_E2E_VERIFY_SSL"), False),
        skip_write=_flag(_get(env_map, file_values, "UNIFI_E2E_SKIP_WRITE"), False),
        config_path=path if path is not None and path.is_file() else None,
    )
    return settings, password


def missing_config_message() -> str:
    searched = ", ".join(str(p) for p in candidate_config_paths())
    return (
        "Live e2e credentials not found. Run ./scripts/init_e2e_config.sh "
        f"or set UNIFI_E2E_HOST/USERNAME/PASSWORD (searched: {searched})"
    )