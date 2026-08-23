# requests-unifi-auth

[![PYPI](https://img.shields.io/pypi/v/requests-unifi-auth)](https://pypi.org/project/requests-unifi-auth/) [![coverage](https://akinfold.github.io/requests-unifi-auth/badges/coverage.svg)](https://github.com/akinfold/requests-unifi-auth/actions) [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/akinfold/requests-unifi-auth/blob/main/LICENSE) [![versions](https://img.shields.io/pypi/pyversions/requests-unifi-auth)](https://pypi.org/project/requests-unifi-auth/) [![CodeFactor](https://www.codefactor.io/repository/github/akinfold/requests-unifi-auth/badge)](https://www.codefactor.io/repository/github/akinfold/requests-unifi-auth) [![Downloads](https://static.pepy.tech/badge/requests-unifi-auth)](https://pepy.tech/project/requests-unifi-auth)

Ubiquiti Unifi Controller API authorization class for python requests library. Takes care of authentification and CSRF
handling.

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
>>> auth = UnifiControllerAuth('your_username', 'your_password', '192.168.1.1')
>>> resp = requests.get('https://192.168.1.1/proxy/network/v2/api/site/default/trafficroutes', verify=False, auth=auth)
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
>>> s.auth = UnifiControllerAuth('your_username', 'your_password', '192.168.1.1')
>>> resp = s.get('https://192.168.1.1/proxy/network/v2/api/site/default/trafficroutes', verify=False)
>>> rules = resp.json()
>>> updated_rule = rules[0]
>>> updated_rule['domains'].append({"domain": "test.com", "port_ranges": [], "ports": []})
>>> resp = s.put('https://192.168.1.1/proxy/network/v2/api/site/default/trafficroutes/68fd349fcs1d3724f0021e3t', json=updated_rule, verify=False)
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
- Role: **Admin** (or Site Admin) on the Network application for the site you will hit
  (usually `default`), with permission to create and delete **Firewall Address Groups**
- Do not grant Owner / Super Admin, SSH, or access to Protect / Access / Talk unless you must
- Use a long random password stored only in the config file (or a password manager)

For read-only accounts, set `UNIFI_E2E_SKIP_WRITE=true` in the config file.

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

```bash
pip install -e ".[test]"
pytest -m e2e
```

On success, `COMPATIBILITY.md` is updated; commit it when you want to publish the result.
On failure, redacted diagnostics are written to `e2e-diagnostics.md` — attach that file when
opening a GitHub issue (use the **E2E failure** template). Never paste passwords, cookies, or
raw CSRF tokens.
