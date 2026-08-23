"""Sanitize and persist live e2e diagnostics for bug reports."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

from requests_unifi_auth import __version__ as PACKAGE_VERSION

REPO_ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTICS_PATH = REPO_ROOT / "e2e-diagnostics.md"

@dataclass
class HttpStep:
    label: str
    method: str
    path: str
    status_code: Optional[int]
    request_header_flags: Dict[str, bool]
    response_header_flags: Dict[str, bool]
    body_length: int
    error: Optional[str] = None


@dataclass
class DiagnosticsCollector:
    steps: List[HttpStep] = field(default_factory=list)
    network_version: Optional[str] = None
    os_version: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    controller_host: Optional[str] = None

    def record_response(
        self,
        label: str,
        response: requests.Response,
        *,
        error: Optional[str] = None,
    ) -> None:
        parsed = urlparse(response.url)
        self.steps.append(
            HttpStep(
                label=label,
                method=response.request.method or "",
                path=parsed.path or "/",
                status_code=response.status_code,
                request_header_flags=_header_presence(response.request.headers),
                response_header_flags=_header_presence(response.headers),
                body_length=len(response.content or b""),
                error=error,
            )
        )

    def record_error(self, label: str, method: str, url: str, exc: BaseException) -> None:
        parsed = urlparse(url)
        self.steps.append(
            HttpStep(
                label=label,
                method=method,
                path=parsed.path or "/",
                status_code=None,
                request_header_flags={},
                response_header_flags={},
                body_length=0,
                error=f"{type(exc).__name__}: {exc}",
            )
        )

    def render_markdown(self) -> str:
        lines = [
            "# e2e diagnostics (redacted)",
            "",
            f"- Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            f"- Package: requests-unifi-auth {PACKAGE_VERSION}",
            f"- Python: {sys.version.split()[0]} ({platform.system()} {platform.release()})",
            f"- requests: {requests.__version__}",
            f"- Controller host: {_redact_host(self.controller_host)}",
            f"- UniFi Network (probed): {self.network_version or 'unknown'}",
            f"- UniFi OS (probed): {self.os_version or 'unknown'}",
            "",
            "## Notes",
            "",
        ]
        if self.notes:
            lines.extend(f"- {note}" for note in self.notes)
        else:
            lines.append("- (none)")
        lines.extend(["", "## HTTP steps", ""])
        if not self.steps:
            lines.append("(no steps recorded)")
        for index, step in enumerate(self.steps, start=1):
            lines.append(f"### {index}. {step.label}")
            lines.append("")
            lines.append(f"- {step.method} `{step.path}`")
            lines.append(f"- status: {step.status_code if step.status_code is not None else 'n/a'}")
            lines.append(f"- body_length: {step.body_length}")
            lines.append(
                f"- request headers present: {_format_flags(step.request_header_flags)}"
            )
            lines.append(
                f"- response headers present: {_format_flags(step.response_header_flags)}"
            )
            if step.error:
                lines.append(f"- error: `{step.error}`")
            lines.append("")
        lines.extend(
            [
                "## How to report",
                "",
                "Open a GitHub issue with the **E2E failure** template and paste this file",
                "(or attach it). Do not include passwords, cookies, or raw CSRF tokens.",
                "",
            ]
        )
        return "\n".join(lines)

    def write(self, path: Path = DIAGNOSTICS_PATH) -> Path:
        path.write_text(self.render_markdown(), encoding="utf-8")
        return path

    def issue_body(self) -> str:
        return (
            "## Environment\n\n"
            f"- requests-unifi-auth: `{PACKAGE_VERSION}`\n"
            f"- Python: `{sys.version.split()[0]}`\n"
            f"- OS: `{platform.system()} {platform.release()}`\n"
            f"- UniFi Network: `{self.network_version or 'unknown'}`\n"
            f"- UniFi OS: `{self.os_version or 'unknown'}`\n\n"
            "## Diagnostics\n\n"
            "```markdown\n"
            f"{self.render_markdown()}\n"
            "```\n"
        )


def _header_presence(headers: Any) -> Dict[str, bool]:
    lower = {str(key).lower(): True for key in headers.keys()}
    return {
        name: bool(lower.get(name))
        for name in sorted(
            {
                "cookie",
                "set-cookie",
                "x-csrf-token",
                "x-updated-csrf-token",
                "content-type",
            }
        )
    }


def _format_flags(flags: Dict[str, bool]) -> str:
    if not flags:
        return "(none)"
    return ", ".join(f"{name}={'yes' if present else 'no'}" for name, present in flags.items())


def _redact_host(host: Optional[str]) -> str:
    if not host:
        return "unknown"
    # Keep hostname shape but avoid leaking credentials if someone pasted user@host.
    if "@" in host:
        host = host.rsplit("@", 1)[-1]
    return host
