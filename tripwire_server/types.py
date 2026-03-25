from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Generic, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class ListResult(Generic[T]):
    items: list[T]
    limit: int
    has_more: bool
    next_cursor: str | None = None


@dataclass(frozen=True)
class ResultSummary:
    event_id: str
    verdict: str
    risk_score: int
    phase: str | None
    provisional: bool | None
    manipulation_score: int | None
    manipulation_verdict: str | None
    evaluation_duration: int | None
    scored_at: str


@dataclass(frozen=True)
class FingerprintReference:
    object: str
    id: str
    confidence: int | None
    timestamp: str | None


@dataclass(frozen=True)
class SessionMetadata:
    user_agent: str
    url: str
    screen_size: str | None
    touch_device: bool | None
    client_ip: str


@dataclass(frozen=True)
class SessionLatestResultDetail(ResultSummary):
    visitor_id: str | None
    metadata: SessionMetadata


@dataclass(frozen=True)
class SessionSummary:
    object: str
    id: str
    created_at: str | None
    latest_event_id: str
    latest_result: ResultSummary
    fingerprint: FingerprintReference | None
    last_scored_at: str


@dataclass(frozen=True)
class SessionDetail:
    object: str
    id: str
    created_at: str | None
    latest_event_id: str
    latest_result: SessionLatestResultDetail
    ip_intel: dict[str, Any] | None
    fingerprint: FingerprintReference | None
    result_history: list[ResultSummary]


@dataclass(frozen=True)
class FingerprintSummary:
    object: str
    id: str
    first_seen_at: str
    last_seen_at: str
    seen_count: int
    last_user_agent: str
    last_ip: str
    expires_at: str
    anchor_webgl_hash: str | None
    anchor_params_hash: str | None
    anchor_audio_hash: str | None
    fingerprint_vector: list[int]
    has_cookie: bool
    has_ls: bool
    has_idb: bool
    has_sw: bool
    has_wn: bool


@dataclass(frozen=True)
class FingerprintSessionSummary:
    event_id: str
    verdict: str
    risk_score: int
    scored_at: str
    user_agent: str
    url: str
    client_ip: str
    screen_size: str | None
    category_scores: dict[str, int] | None


@dataclass(frozen=True)
class FingerprintDetail(FingerprintSummary):
    sessions: list[FingerprintSessionSummary]


@dataclass(frozen=True)
class Team:
    object: str
    id: str
    name: str
    slug: str
    status: str
    created_at: str
    updated_at: str | None


@dataclass(frozen=True)
class ApiKey:
    object: str
    id: str
    key: str
    name: str
    is_test: bool
    allowed_origins: list[str] | None
    rate_limit: int | None
    status: str
    created_at: str
    rotated_at: str | None
    revoked_at: str | None


@dataclass(frozen=True)
class IssuedApiKey(ApiKey):
    secret_key: str


@dataclass(frozen=True)
class VerifiedTripwireSignal:
    id: str
    category: str
    confidence: str
    score: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerifiedTripwireToken:
    event_id: str
    session_id: str
    verdict: str
    score: int
    manipulation_score: int | None
    manipulation_verdict: str | None
    evaluation_duration: int | None
    scored_at: int
    metadata: SessionMetadata
    signals: list[VerifiedTripwireSignal]
    category_scores: dict[str, int]
    bot_attribution: dict[str, Any] | None
    visitor_id: str | None
    visitor_id_confidence: int | None
    embed_context: dict[str, Any] | None
    phase: str | None
    provisional: bool | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    data: VerifiedTripwireToken | None = None
    error: Exception | None = None
