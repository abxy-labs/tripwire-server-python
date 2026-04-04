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
class DecisionManipulation:
    score: int | None
    verdict: str | None


@dataclass(frozen=True)
class Decision:
    event_id: str
    verdict: str
    risk_score: int
    phase: str | None
    is_provisional: bool | None
    manipulation: DecisionManipulation | None
    evaluation_duration_ms: int | None
    evaluated_at: str


@dataclass(frozen=True)
class VisitorFingerprintLink:
    object: str
    id: str
    confidence: int | None
    identified_at: str | None


@dataclass(frozen=True)
class RequestContext:
    user_agent: str
    url: str
    screen_size: str | None
    is_touch_capable: bool | None
    ip_address: str


@dataclass(frozen=True)
class SessionDetailRequest:
    url: str
    referrer: str | None
    user_agent: str


@dataclass(frozen=True)
class SessionDecision:
    event_id: str
    automation_status: str
    risk_score: int
    evaluation_phase: str | None
    decision_status: str
    evaluated_at: str


@dataclass(frozen=True)
class SessionSummary:
    object: str
    id: str
    created_at: str | None
    latest_decision: Decision
    visitor_fingerprint: VisitorFingerprintLink | None


@dataclass(frozen=True)
class SessionDetail:
    object: str
    id: str
    created_at: str | None
    decision: SessionDecision
    highlights: list[dict[str, Any]]
    automation: dict[str, Any] | None
    web_bot_auth: dict[str, Any] | None
    network: dict[str, Any]
    runtime_integrity: dict[str, Any]
    visitor_fingerprint: dict[str, Any] | None
    connection_fingerprint: dict[str, Any]
    previous_decisions: list[SessionDecision]
    request: SessionDetailRequest
    browser: dict[str, Any]
    device: dict[str, Any]
    analysis_coverage: dict[str, bool]
    signals_fired: list[dict[str, Any]]
    client_telemetry: dict[str, Any]


@dataclass(frozen=True)
class VisitorFingerprintLifecycle:
    first_seen_at: str
    last_seen_at: str
    seen_count: int
    expires_at: str


@dataclass(frozen=True)
class VisitorFingerprintLatestRequest:
    user_agent: str
    ip_address: str


@dataclass(frozen=True)
class VisitorFingerprintStorage:
    cookies: bool
    local_storage: bool
    indexed_db: bool
    service_worker: bool
    window_name: bool


@dataclass(frozen=True)
class VisitorFingerprintAnchors:
    webgl_hash: str | None
    parameters_hash: str | None
    audio_hash: str | None


@dataclass(frozen=True)
class VisitorFingerprintSummary:
    object: str
    id: str
    lifecycle: VisitorFingerprintLifecycle
    latest_request: VisitorFingerprintLatestRequest
    storage: VisitorFingerprintStorage
    anchors: VisitorFingerprintAnchors


@dataclass(frozen=True)
class ScoreBreakdown:
    categories: dict[str, int]


@dataclass(frozen=True)
class VisitorFingerprintSessionSummary:
    session_id: str
    decision: Decision
    request: RequestContext
    score_breakdown: ScoreBreakdown


@dataclass(frozen=True)
class VisitorFingerprintComponents:
    vector: list[int]


@dataclass(frozen=True)
class VisitorFingerprintActivity:
    sessions: list[VisitorFingerprintSessionSummary]


@dataclass(frozen=True)
class VisitorFingerprintDetail(VisitorFingerprintSummary):
    components: VisitorFingerprintComponents
    activity: VisitorFingerprintActivity


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
    public_key: str
    name: str
    environment: str
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
class GateServiceEnvVar:
    name: str
    key: str
    secret: bool


@dataclass(frozen=True)
class GateServiceSdkInstall:
    label: str
    install: str
    url: str


@dataclass(frozen=True)
class GateServiceBranding:
    verified: bool
    logo_url: str | None = None
    primary_color: str | None = None
    secondary_color: str | None = None
    ascii_art: str | None = None


@dataclass(frozen=True)
class GateServiceConsent:
    terms_url: str | None = None
    privacy_url: str | None = None


@dataclass(frozen=True)
class GateRegistryEntry:
    id: str
    status: str
    discoverable: bool
    name: str
    description: str
    website: str
    env_vars: list[GateServiceEnvVar]
    docs_url: str
    sdks: list[GateServiceSdkInstall]
    branding: GateServiceBranding
    consent: GateServiceConsent
    dashboard_login_url: str | None = None


@dataclass(frozen=True)
class GateManagedService:
    object: str
    id: str
    status: str
    discoverable: bool
    name: str
    description: str
    website: str
    dashboard_login_url: str | None
    webhook_url: str
    env_vars: list[GateServiceEnvVar]
    docs_url: str
    sdks: list[GateServiceSdkInstall]
    branding: GateServiceBranding
    consent: GateServiceConsent
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class GateDeliveryRequest:
    version: int
    algorithm: str
    key_id: str
    public_key: str


@dataclass(frozen=True)
class GateDeliveryEnvelope:
    version: int
    algorithm: str
    key_id: str
    ephemeral_public_key: str
    salt: str
    iv: str
    ciphertext: str
    tag: str


@dataclass(frozen=True)
class GateDeliveryBundle:
    integrator: GateDeliveryEnvelope
    gate: GateDeliveryEnvelope


@dataclass(frozen=True)
class GateSessionCreate:
    object: str
    id: str
    status: str
    poll_token: str
    consent_url: str
    expires_at: str


@dataclass(frozen=True)
class GateSessionPollData:
    object: str
    id: str
    status: str
    expires_at: str | None = None
    gate_account_id: str | None = None
    account_name: str | None = None
    delivery_bundle: GateDeliveryBundle | None = None
    docs_url: str | None = None


@dataclass(frozen=True)
class GateSessionDeliveryAcknowledgement:
    object: str
    gate_session_id: str
    status: str


@dataclass(frozen=True)
class GateLoginSession:
    object: str
    id: str
    status: str
    consent_url: str
    expires_at: str


@dataclass(frozen=True)
class GateDashboardLogin:
    object: str
    gate_account_id: str
    account_name: str


@dataclass(frozen=True)
class AgentTokenVerification:
    valid: bool
    gate_account_id: str | None = None
    status: str | None = None
    created_at: str | None = None
    expires_at: str | None = None


@dataclass(frozen=True)
class VerifiedTripwireSignal:
    id: str
    category: str
    confidence: str
    score: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class Attribution:
    bot: dict[str, Any] | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerifiedTripwireToken:
    object: str
    session_id: str
    decision: Decision
    request: RequestContext
    visitor_fingerprint: VisitorFingerprintLink | None
    signals: list[VerifiedTripwireSignal]
    score_breakdown: ScoreBreakdown
    attribution: Attribution
    embed: dict[str, Any] | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    data: VerifiedTripwireToken | None = None
    error: Exception | None = None
