# unifi-requests
Minimalistic Ubiquiti Unifi controller API client which takes care of authentication and CSRF handling.

## Examples

### Read traffic policy-based routes

```pycon
>>> import json
>>> import requests
>>> from unifi_requests.auth import UnifiControllerAuth
>>> auth = UnifiControllerAuth('https://192.168.1.1', 'your_username', 'your_password')
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
>>> from unifi_requests.auth import UnifiControllerAuth
>>> s = requests.Session()
>>> s.auth = UnifiControllerAuth('https://192.168.1.1', 'your_username', 'your_password')
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
