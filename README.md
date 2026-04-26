# Tripwire Python Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Python library provides convenient access to the Tripwire API from applications written in Python. It includes a synchronous client for Sessions, Fingerprints, Teams, Team API key management, sealed token verification, Gate, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- iterator helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- public, bearer-token, and secret-key auth modes for Gate flows
- Gate delivery/webhook helpers

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
pip install tripwire-server
```

## Requirements

- Python 3.10+

## Usage

Use `TRIPWIRE_SECRET_KEY` or `secret_key=...` for core detect APIs. For public or bearer-auth Gate flows, the client can also be created without a secret key:

```python
from tripwire_server import Tripwire

client = Tripwire(secret_key="sk_live_...")

page = client.sessions.list(verdict="bot", limit=25)
session = client.sessions.get("sid_123")
```

### Sealed token verification

```python
from tripwire_server import safe_verify_tripwire_token

result = safe_verify_tripwire_token(
    sealed_token,
    "sk_live_...",
)

if result.ok:
    print(result.data.verdict, result.data.score)
else:
    print(result.error)
```

### Pagination

```python
for session in client.sessions.iter(search="signup"):
    print(session.id, session.latest_decision.verdict)
```

### Fingerprints

```python
page = client.fingerprints.list(sort="seen_count")
fingerprint = client.fingerprints.get("vid_123")
```

### Teams

```python
team = client.teams.get("team_123")
updated = client.teams.update("team_123", name="New Name")
```

### Team API keys

```python
created = client.teams.api_keys.create(
    "team_123",
    name="Production",
    allowed_origins=["https://example.com"],
)

client.teams.api_keys.revoke("team_123", created.id)
```

### Gate APIs

```python
from tripwire_server import Tripwire, create_delivery_key_pair

client = Tripwire()
services = client.gate.registry.list()
session = client.gate.sessions.create(
    service_id="tripwire",
    account_name="my-project",
    delivery=create_delivery_key_pair().delivery,
)

print(services[0].id, session.consent_url)
```

### Gate delivery and webhook helpers

```python
from tripwire_server import (
    create_delivery_key_pair,
    create_gate_approved_webhook_response,
    decrypt_gate_delivery_envelope,
    parse_webhook_event,
    verify_gate_webhook_signature,
)

key_pair = create_delivery_key_pair()
response = create_gate_approved_webhook_response(
    {
        "delivery": key_pair.delivery,
        "outputs": {
            "TRIPWIRE_PUBLISHABLE_KEY": "pk_live_...",
            "TRIPWIRE_SECRET_KEY": "sk_live_...",
        },
    }
)
payload = decrypt_gate_delivery_envelope(key_pair.private_key, response.encrypted_delivery)
print(payload.outputs["TRIPWIRE_SECRET_KEY"])
raw_body = '{"id":"wevt_123","object":"webhook_event","type":"webhook.test","created":"2026-04-26T00:00:00.000Z","data":{}}'
print(
    verify_gate_webhook_signature(
        secret="whsec_test",
        timestamp="1735776000",
        raw_body=raw_body,
        signature="…",
    )
)
event = parse_webhook_event(raw_body)
print(event.type)
```

### Error handling

```python
from tripwire_server import TripwireApiError

try:
    client.sessions.list(limit=999)
except TripwireApiError as error:
    print(error.status, error.code, error.message)
```

## Support

If you need help integrating Tripwire, start with [tripwirejs.com/docs](https://tripwirejs.com/docs).
