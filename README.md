# `tripwire-server`

Official Tripwire Python server SDK.

`tripwire-server` exposes the customer-facing server APIs for:

- Sessions API
- Fingerprints API
- Teams API
- Team API key management
- sealed token verification

It does not include collect endpoints or internal scoring APIs.

## Installation

```bash
pip install tripwire-server
```

## Quick start

```python
from tripwire_server import Tripwire, safe_verify_tripwire_token

client = Tripwire(secret_key="sk_live_...")

sessions = client.sessions.list(verdict="bot", limit=25)
session = client.sessions.get("sid_123")

result = safe_verify_tripwire_token("AQAA...", "sk_live_...")
if result.ok:
    print(result.data.verdict, result.data.score)
```

## Constructor

```python
Tripwire(
    secret_key=None,
    base_url="https://api.tripwirejs.com",
    timeout=30.0,
    user_agent=None,
)
```

Defaults:

- `secret_key`: `TRIPWIRE_SECRET_KEY`
- `base_url`: `https://api.tripwirejs.com`
- `timeout`: `30.0` seconds

## Examples

### Sessions

```python
page = client.sessions.list(verdict="human", limit=50)

for session in client.sessions.iter(search="signup"):
    print(session.id, session.latest_result.verdict)
```

### Fingerprints

```python
page = client.fingerprints.list(sort="seen_count")
fingerprint = client.fingerprints.get("vis_123")
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

## Development

The canonical cross-language server SDK spec lives in the Tripwire main repo under `sdk-spec/server/`.
This repo carries a synced copy in `spec/` for standalone testing and release workflows.
