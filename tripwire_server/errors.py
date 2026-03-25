from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class TripwireConfigurationError(Exception):
    """Raised when the client is missing required configuration."""


class TripwireTokenVerificationError(Exception):
    """Raised when a sealed Tripwire token cannot be verified."""


@dataclass(slots=True)
class TripwireApiError(Exception):
    status: int
    code: str
    message: str
    request_id: str | None = None
    field_errors: list[dict[str, Any]] = field(default_factory=list)
    docs_url: str | None = None
    body: Any = None

    def __str__(self) -> str:
        return self.message
