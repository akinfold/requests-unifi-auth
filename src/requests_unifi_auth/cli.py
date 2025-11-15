import re
import sys
import json
from typing import Tuple, Dict, List, Optional

import click
import requests

from requests_unifi_auth import UnifiControllerAuth

AUTH_REGEXP = re.compile(r'^(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>[^\s]+)\s*')
"""Match auth strings like 'foo:bar@192.168.1.1'."""


def _parse_kv(pairs: Tuple[str, ...]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for p in pairs or ():
        if "=" in p:
            k, v = p.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            # allow header-like "Key: Value"
            if ":" in p:
                k, v = p.split(":", 1)
                result[k.strip()] = v.strip()
            else:
                # fallback: treat as flag-like header with empty value
                result[p.strip()] = ""
    return result


def _parse_auth(auth: Optional[str]) -> Optional[Tuple[str, str, str]]:
    if not auth:
        return None

    if auth.startswith('@'):
        # allow @filename to load auth data from file
        path = auth[1:]
        with open(path, "r", encoding="utf-8") as f:
            auth = f.read()

    match = AUTH_REGEXP.match(auth)
    if match:
        user, password, host = match.groups()
        return user, password, host

    return None


def _merge_params(params_list: Tuple[str, ...]) -> Dict[str, str]:
    return _parse_kv(params_list)


def _load_json(json_text: Optional[str]) -> Optional[object]:
    if not json_text:
        return None
    # allow @filename to load json from file
    if json_text.startswith("@"):
        path = json_text[1:]
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    try:
        return json.loads(json_text)
    except json.JSONDecodeError:
        # treat as plain string
        return json_text


def _request(
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Dict[str, str],
    data: List[str],
    json_body,
    auth: Tuple[str, str, str],
    timeout: Optional[float],
    allow_redirects: bool,
    verify: bool,
):
    kwargs = {
        "headers": headers or None,
        "params": params or None,
        "timeout": timeout,
        "allow_redirects": allow_redirects,
        "verify": verify,
    }
    if auth:
        kwargs["auth"] = UnifiControllerAuth(*auth)
    if json_body is not None:
        kwargs["json"] = json_body
    elif data:
        # if multiple data entries, send last one as body; for form data, user can pass key=value headers
        if len(data) == 1:
            v = data[0]
            if v.startswith("@"):
                with open(v[1:], "rb") as f:
                    kwargs["data"] = f.read()
            else:
                kwargs["data"] = v
        else:
            # multiple data entries -> send as form-encoded dict
            kwargs["data"] = _parse_kv(tuple(data))

    resp = requests.request(method=method, url=url, **kwargs)
    return resp


def _print_response(resp: requests.Response, show_headers: bool, pretty: bool, output: Optional[str], status_only: bool):
    if status_only:
        click.echo(str(resp.status_code))
        return

    if show_headers:
        click.echo(f"HTTP/{resp.raw.version if hasattr(resp.raw, 'version') else '1.1'} {resp.status_code} {resp.reason}")
        for k, v in resp.headers.items():
            click.echo(f"{k}: {v}")
        click.echo("")

    content_type = resp.headers.get("Content-Type", "")
    body_bytes = resp.content

    if output:
        mode = "wb"
        with open(output, mode) as f:
            f.write(body_bytes)
        click.echo(f"Wrote response body to {output}")
        return

    # try to decode as text
    try:
        text = resp.text
    except Exception:
        text = None

    if pretty and ("application/json" in content_type or (text and (text.strip().startswith("{") or text.strip().startswith("[")))):
        try:
            parsed = resp.json()
            click.echo(json.dumps(parsed, indent=2, ensure_ascii=False))
            return
        except Exception:
            pass

    # fallback to raw text or binary print as repr
    if text is not None:
        click.echo(text)
    else:
        click.echo(repr(body_bytes))


def common_options(func):
    options = [
        click.option("-H", "--header", multiple=True, help="Header, e.g. -H 'Accept: application/json' or -H 'X-Api-Key=VALUE'"),
        click.option("-p", "--param", "params", multiple=True, help="Query param, e.g. -p 'key=value'"),
        click.option("-d", "--data", "data", multiple=True, help="Request body or form field. Use @filename to read file"),
        click.option("-j", "--json", "json_text", help="JSON body as string or @filename to read"),
        click.option("-a", "--auth", help="Auth data as user:pass@host. For example: 'foo:bar@192.168.1.1'. Use @filename to read data from file."),
        click.option("-t", "--timeout", type=float, default=30.0, show_default=True, help="Request timeout in seconds"),
        click.option("--no-allow-redirects", "allow_redirects", flag_value=False, default=True, help="Disable redirects"),
        click.option("--no-verify", "verify", flag_value=False, default=True, help="Disable SSL verification"),
        click.option("-o", "--output", help="Write response body to file"),
        click.option("--no-pretty", "pretty", flag_value=False, default=True, help="Disable pretty printing of JSON"),
        click.option("--show-headers/--no-show-headers", default=False, help="Show response headers"),
        click.option("--status-only", is_flag=True, default=False, help="Only print response HTTP status code"),
    ]
    for opt in reversed(options):
        func = opt(func)
    return func


@click.group()
def cli():
    """Simple requests-like CLI using click."""
    pass


@cli.command()
@common_options
@click.argument("url")
def get(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP GET"""
    _run("GET", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def post(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP POST"""
    _run("POST", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def put(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP PUT"""
    _run("PUT", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def delete(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP DELETE"""
    _run("DELETE", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def head(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP HEAD"""
    _run("HEAD", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def options(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP OPTIONS"""
    _run("OPTIONS", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


@cli.command()
@common_options
@click.argument("url")
def patch(url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    """HTTP PATCH"""
    _run("PATCH", url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only)


def _run(method, url, header, params, data, json_text, auth, timeout, allow_redirects, verify, output, pretty, show_headers, status_only):
    headers = _parse_kv(header)
    params_d = _merge_params(params)
    json_body = _load_json(json_text)
    auth_data = _parse_auth(auth)
    try:
        resp = _request(
            method=method,
            url=url,
            headers=headers,
            params=params_d,
            data=list(data),
            json_body=json_body,
            auth=auth_data,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify,
        )
    except requests.RequestException as e:
        click.echo(f"Request failed: {e}", err=True)
        sys.exit(2)

    _print_response(resp, show_headers=show_headers, pretty=pretty, output=output, status_only=status_only)
    # exit with non-zero if status >= 400
    if resp.status_code >= 400:
        sys.exit(1)


if __name__ == "__main__":
    cli()