# requests-unifi-auth
[![cov](https://akinfold.github.io/requests-unifi-auth/badges/coverage.svg)](https://github.com/akinfold/requests-unifi-auth/actions)

Ubiquiti Unifi Controller API authorization class for python requests library. Takes care of authentification and CSRF handling.

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
