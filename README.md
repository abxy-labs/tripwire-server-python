# Tripwire Python Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Python library provides convenient access to the Tripwire API from applications written in Python. It includes a synchronous client for Sessions, Fingerprints, Teams, Team API key management, and sealed token verification.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- iterator helpers for cursor-based pagination
- structured API errors and built-in sealed token verification

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

The library needs to be configured with your account's secret key. Set `TRIPWIRE_SECRET_KEY` in your environment or pass `secret_key` directly:

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
