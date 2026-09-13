# requests-unifi-auth

[![PYPI](https://img.shields.io/pypi/v/requests-unifi-auth)](https://pypi.org/project/requests-unifi-auth/) [![coverage](https://akinfold.github.io/requests-unifi-auth/badges/coverage.svg)](https://github.com/akinfold/requests-unifi-auth/actions) [![UniFi Network](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/akinfold/requests-unifi-auth/main/badges/unifi-network.json)](https://github.com/akinfold/requests-unifi-auth/blob/main/COMPATIBILITY.md) [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/akinfold/requests-unifi-auth/blob/main/LICENSE) [![versions](https://img.shields.io/pypi/pyversions/requests-unifi-auth)](https://pypi.org/project/requests-unifi-auth/) [![CodeFactor](https://www.codefactor.io/repository/github/akinfold/requests-unifi-auth/badge)](https://www.codefactor.io/repository/github/akinfold/requests-unifi-auth) [![Downloads](https://static.pepy.tech/badge/requests-unifi-auth)](https://pepy.tech/project/requests-unifi-auth)

Authentication for the UniFi Controller and UniFi OS Web UI APIs using Python
Requests. The auth handler manages login cookies, CSRF tokens, and one bounded
reauthentication attempt.

For a curl-like command-line interface built on this package, see
[`uictlapi`](https://github.com/akinfold/uictlapi).

## Installation

```bash
pip install requests-unifi-auth
```

## Examples

### Read traffic policy-based routes

```pycon
>>> import json
>>> import requests
>>> from requests_unifi_auth import UnifiControllerAuth
>>> auth = UnifiControllerAuth("your_username", "your_password", "controller.example")
>>> resp = requests.get(
...     "https://controller.example/proxy/network/v2/api/site/default/trafficroutes",
...     auth=auth,
... )
>>> print(json.dumps(resp.json(), indent=4))
[
    {
        "_id": "68fd349fcs1d3724f0021e3t",
        "description": "My Cool Domains Rule",
        "domains": [
            {
                "domain": "example.com",
                "port_ranges": [],
                "ports": []
            }
        ],
        "enabled": true,
        "ip_addresses": [],
        "ip_ranges": [],
        "kill_switch_enabled": true,
        "matching_target": "DOMAIN",
        "network_id": "78fd3e21c31v5424f0021d25",
        "next_hop": "",
        "regions": [],
        "target_devices": [
            {
                "type": "ALL_CLIENTS"
            }
        ]
    },
    {
        "_id": "68fd3ff1x31d2224d2023f56",
        "description": "Yet Another Cool Domain Rule",
        "domains": [
            {
                "domain": "foo.com",
                "port_ranges": [],
                "ports": []
            },
            {
                "domain": "bar.com",
                "port_ranges": [],
                "ports": []
            }
        ],
        "enabled": true,
        "ip_addresses": [],
        "ip_ranges": [],
        "kill_switch_enabled": false,
        "matching_target": "DOMAIN",
        "network_id": "78fd3e21c31v5424f0021d25",
        "next_hop": "",
        "regions": [],
        "target_devices": [
            {
                "type": "ALL_CLIENTS"
            }
        ]
    }
]
```

### Update traffic policy-based route

```pycon
>>> import json
>>> import requests
>>> from requests_unifi_auth import UnifiControllerAuth
>>> s = requests.Session()
>>> s.auth = UnifiControllerAuth("your_username", "your_password", "controller.example")
>>> resp = s.get(
...     "https://controller.example/proxy/network/v2/api/site/default/trafficroutes"
... )
>>> rules = resp.json()
>>> updated_rule = rules[0]
>>> updated_rule["domains"].append({"domain": "test.com", "port_ranges": [], "ports": []})
>>> resp = s.put(
...     "https://controller.example/proxy/network/v2/api/site/default/trafficroutes/68fd349fcs1d3724f0021e3t",
...     json=updated_rule,
... )
>>> print(json.dumps(resp.json(), indent=4))
{
    "_id": "68fd349fcs1d3724f0021e3t",
    "description": "My Cool Domains Rule",
    "domains": [
        {
            "domain": "example.com",
            "port_ranges": [],
            "ports": []
        },
        {
            "domain": "test.com", 
            "port_ranges": [], 
            "ports": []
        }
    ],
    "enabled": true,
    "ip_addresses": [],
    "ip_ranges": [],
    "kill_switch_enabled": true,
    "matching_target": "DOMAIN",
    "network_id": "78fd3e21c31v5424f0021d25",
    "next_hop": "",
    "regions": [],
    "target_devices": [
        {
            "type": "ALL_CLIENTS"
        }
    ]
}
```

## Security and request behavior

`controller_netloc` is an authority, such as `controller.example`,
`controller.example:8443`, or `[2001:db8::10]:8443`. HTTPS is the default and
the login URL is derived only from this configured authority. Hostname case,
IDNA, bracketed IPv6, and default ports are normalized before comparison.

The handler sends managed cookies and CSRF tokens only to that exact origin.
It rejects cross-origin and HTTPS-to-HTTP redirects with
`UnsafeRedirectError`. A same-origin redirect is followed only before the auth
handler has any cookie or CSRF state, and only when neither the request nor the
redirect response carries that state. After the first successful login, every
redirect for that auth instance is rejected, including redirects from later
requests. This check also raises when the caller uses `allow_redirects=False`,
because a bare Requests `AuthBase` hook cannot observe that option or safely
replace the session cookie jar during later redirect processing. Send a new
request to the inspected target if your controller relies on that flow.

Response hooks registered after this auth handler are trusted not to rewrite
the response URL or `Location` header. An `AuthBase` hook cannot revalidate a
target changed by a later hook. The internal login response is never exposed in
`Response.history`; on an outer redirect chain, Requests may also omit the
challenged `401` handled internally. Do not use `Response.history` as an audit
log of authentication attempts.

Plaintext HTTP authentication requires both explicit settings:

```python
auth = UnifiControllerAuth(
    "user",
    "password",
    "controller.example",
    scheme="http",
    allow_insecure_http=True,
)
```

This sends the password without transport encryption. Use it only in an
isolated test environment. `verify=False` is different: it keeps encryption
but disables server identity verification. Prefer a trusted certificate or a
CA bundle:

```python
session = requests.Session()
session.verify = "/path/to/controller-ca.pem"
session.auth = UnifiControllerAuth("user", "password", "controller.example")
```

The handler retries a challenged request at most once. It rewinds seekable
bodies to their original position and raises Requests'
`UnrewindableBodyError` before retrying a generator or another body that cannot
be replayed safely. Authentication state is synchronized across concurrent
requests, but Requests does not guarantee that arbitrary concurrent use of one
`Session` is thread-safe.

## Compatibility

See [COMPATIBILITY.md](COMPATIBILITY.md) for live end-to-end results against real UniFi
controllers.

## Live end-to-end tests

These tests talk to a real controller on your LAN. They are skipped in CI and in a default
`pytest` run (`-m "not e2e"`).

### 1. Create a dedicated controller account

In UniFi OS → Admins / Users, add a **local** user used only for these tests (do not use your
owner / Super Admin account):

- Username example: `e2e-requests-unifi-auth`
- Role: a least-privilege Network application role for the site under test
  (currently `default`) that can create, update, and delete user groups
- Do not grant Owner / Super Admin, SSH, or access to Protect / Access / Talk unless you must
- Use a long random password stored only in the config file (or a password manager)

The generated config disables writes. Set `UNIFI_E2E_ENABLE_WRITE=true` only
when the account and controller are suitable for a temporary, unassigned user
group. The test creates and renames one uniquely named group, then deletes it
and verifies that it is absent. A failed or unverifiable cleanup fails the run.

### 2. Create the credentials file (outside the git tree)

Do **not** put passwords inside the repository clone or in cloud-synced folders.

Interactive setup (prompts for host, username, password, TLS and write-test flags):

```bash
chmod +x scripts/init_e2e_config.sh
./scripts/init_e2e_config.sh
```

The script writes `~/.config/requests-unifi-auth/e2e.env` with mode `600` (or
`$XDG_CONFIG_HOME/requests-unifi-auth/e2e.env`). To use another path:

```bash
UNIFI_E2E_CONFIG=/absolute/path/to/e2e.env ./scripts/init_e2e_config.sh
```

Optional overrides after the file exists:

- Environment variables with the same `UNIFI_E2E_*` names override values from the file
- Template without secrets: [`e2e.config.example.env`](e2e.config.example.env)

### 3. Run the live suite

From the repository root, use the project virtualenv (so `pytest` is on `PATH`):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[test]"
pytest -m e2e
```

Without activating the venv:

```bash
.venv/bin/pip install -e ".[test]"
.venv/bin/pytest -m e2e
```

`COMPATIBILITY.md` is updated only when the complete required suite passes with
`UNIFI_E2E_ENABLE_WRITE=true`, including cleanup. A read-only or selected run
does not publish a full compatibility result. Commit the matrix update only
when you want to publish it.
On failure, redacted diagnostics are written to `e2e-diagnostics.md` — attach that file when
opening a GitHub issue (use the **E2E failure** template). Never paste passwords, cookies, or
raw CSRF tokens.
