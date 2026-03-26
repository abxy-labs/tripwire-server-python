from __future__ import annotations

import os
from typing import Any, Iterator

import httpx

from .errors import TripwireApiError, TripwireConfigurationError
from .types import (
    ApiKey,
    Attribution,
    Decision,
    DecisionManipulation,
    IssuedApiKey,
    ListResult,
    RequestContext,
    ScoreBreakdown,
    SessionDetail,
    SessionDecision,
    SessionDetailRequest,
    SessionSummary,
    Team,
    VerifiedTripwireSignal,
    VerificationResult,
    VerifiedTripwireToken,
    VisitorFingerprintActivity,
    VisitorFingerprintAnchors,
    VisitorFingerprintComponents,
    VisitorFingerprintDetail,
    VisitorFingerprintLatestRequest,
    VisitorFingerprintLifecycle,
    VisitorFingerprintLink,
    VisitorFingerprintSessionSummary,
    VisitorFingerprintStorage,
    VisitorFingerprintSummary,
)

DEFAULT_BASE_URL = "https://api.tripwirejs.com"
DEFAULT_TIMEOUT = 30.0
SDK_CLIENT_HEADER = "tripwire-server-python/0.1.0"


def _compact_query(query: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in query.items() if value is not None}


def _parse_decision(data: dict[str, Any]) -> Decision:
    manipulation_raw = data.get("manipulation")
    manipulation = None
    if isinstance(manipulation_raw, dict):
        manipulation = DecisionManipulation(
            score=int(manipulation_raw["score"]) if isinstance(manipulation_raw.get("score"), int) else None,
            verdict=manipulation_raw.get("verdict")
            if isinstance(manipulation_raw.get("verdict"), str) or manipulation_raw.get("verdict") is None
            else None,
        )

    return Decision(
        event_id=str(data["event_id"]),
        verdict=str(data["verdict"]),
        risk_score=int(data["risk_score"]),
        phase=data.get("phase") if isinstance(data.get("phase"), str) or data.get("phase") is None else None,
        is_provisional=data.get("is_provisional")
        if isinstance(data.get("is_provisional"), bool) or data.get("is_provisional") is None
        else None,
        manipulation=manipulation,
        evaluation_duration_ms=int(data["evaluation_duration_ms"])
        if isinstance(data.get("evaluation_duration_ms"), int)
        else None,
        evaluated_at=str(data["evaluated_at"]),
    )


def _parse_request_context(data: dict[str, Any]) -> RequestContext:
    return RequestContext(
        user_agent=str(data["user_agent"]),
        url=str(data["url"]),
        screen_size=data.get("screen_size")
        if isinstance(data.get("screen_size"), str) or data.get("screen_size") is None
        else None,
        is_touch_capable=data.get("is_touch_capable")
        if isinstance(data.get("is_touch_capable"), bool) or data.get("is_touch_capable") is None
        else None,
        ip_address=str(data["ip_address"]),
    )


def _parse_session_detail_request(data: dict[str, Any]) -> SessionDetailRequest:
    return SessionDetailRequest(
        url=str(data["url"]),
        referrer=data.get("referrer")
        if isinstance(data.get("referrer"), str) or data.get("referrer") is None
        else None,
        user_agent=str(data["user_agent"]),
    )


def _parse_session_decision(data: dict[str, Any]) -> SessionDecision:
    return SessionDecision(
        event_id=str(data["event_id"]),
        automation_status=str(data["automation_status"]),
        risk_score=int(data["risk_score"]),
        evaluation_phase=data.get("evaluation_phase")
        if isinstance(data.get("evaluation_phase"), str) or data.get("evaluation_phase") is None
        else None,
        decision_status=str(data["decision_status"]),
        evaluated_at=str(data["evaluated_at"]),
    )


def _parse_visitor_fingerprint_link(data: dict[str, Any] | None) -> VisitorFingerprintLink | None:
    if data is None:
        return None
    return VisitorFingerprintLink(
        object=str(data["object"]),
        id=str(data["id"]),
        confidence=int(data["confidence"]) if isinstance(data.get("confidence"), int) else None,
        identified_at=data.get("identified_at")
        if isinstance(data.get("identified_at"), str) or data.get("identified_at") is None
        else None,
    )


def _parse_session_summary(data: dict[str, Any]) -> SessionSummary:
    return SessionSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("created_at"),
        latest_decision=_parse_decision(dict(data["latest_decision"])),
        visitor_fingerprint=_parse_visitor_fingerprint_link(data.get("visitor_fingerprint")),
    )


def _parse_session_detail(data: dict[str, Any]) -> SessionDetail:
    return SessionDetail(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("created_at"),
        decision=_parse_session_decision(dict(data["decision"])),
        highlights=[dict(item) for item in data.get("highlights", []) if isinstance(item, dict)],
        automation=dict(data.get("automation")) if isinstance(data.get("automation"), dict) else None,
        web_bot_auth=dict(data.get("web_bot_auth")) if isinstance(data.get("web_bot_auth"), dict) else None,
        network=dict(data.get("network", {})) if isinstance(data.get("network"), dict) else {},
        runtime_integrity=dict(data.get("runtime_integrity", {}))
        if isinstance(data.get("runtime_integrity"), dict)
        else {},
        visitor_fingerprint=dict(data.get("visitor_fingerprint"))
        if isinstance(data.get("visitor_fingerprint"), dict)
        else None,
        connection_fingerprint=dict(data.get("connection_fingerprint", {}))
        if isinstance(data.get("connection_fingerprint"), dict)
        else {},
        previous_decisions=[_parse_session_decision(dict(item)) for item in data.get("previous_decisions", [])],
        request=_parse_session_detail_request(dict(data["request"])),
        browser=dict(data.get("browser", {})) if isinstance(data.get("browser"), dict) else {},
        device=dict(data.get("device", {})) if isinstance(data.get("device"), dict) else {},
        analysis_coverage={
            str(key): bool(value)
            for key, value in dict(data.get("analysis_coverage", {})).items()
            if isinstance(key, str)
        }
        if isinstance(data.get("analysis_coverage"), dict)
        else {},
        signals_fired=[dict(item) for item in data.get("signals_fired", []) if isinstance(item, dict)],
        client_telemetry=dict(data.get("client_telemetry", {}))
        if isinstance(data.get("client_telemetry"), dict)
        else {},
    )


def _parse_visitor_fingerprint_summary(data: dict[str, Any]) -> VisitorFingerprintSummary:
    lifecycle_raw = dict(data["lifecycle"])
    latest_request_raw = dict(data["latest_request"])
    storage_raw = dict(data["storage"])
    anchors_raw = dict(data["anchors"])

    return VisitorFingerprintSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        lifecycle=VisitorFingerprintLifecycle(
            first_seen_at=str(lifecycle_raw["first_seen_at"]),
            last_seen_at=str(lifecycle_raw["last_seen_at"]),
            seen_count=int(lifecycle_raw["seen_count"]),
            expires_at=str(lifecycle_raw["expires_at"]),
        ),
        latest_request=VisitorFingerprintLatestRequest(
            user_agent=str(latest_request_raw["user_agent"]),
            ip_address=str(latest_request_raw["ip_address"]),
        ),
        storage=VisitorFingerprintStorage(
            cookies=bool(storage_raw["cookies"]),
            local_storage=bool(storage_raw["local_storage"]),
            indexed_db=bool(storage_raw["indexed_db"]),
            service_worker=bool(storage_raw["service_worker"]),
            window_name=bool(storage_raw["window_name"]),
        ),
        anchors=VisitorFingerprintAnchors(
            webgl_hash=anchors_raw.get("webgl_hash")
            if isinstance(anchors_raw.get("webgl_hash"), str) or anchors_raw.get("webgl_hash") is None
            else None,
            parameters_hash=anchors_raw.get("parameters_hash")
            if isinstance(anchors_raw.get("parameters_hash"), str) or anchors_raw.get("parameters_hash") is None
            else None,
            audio_hash=anchors_raw.get("audio_hash")
            if isinstance(anchors_raw.get("audio_hash"), str) or anchors_raw.get("audio_hash") is None
            else None,
        ),
    )


def _parse_score_breakdown(data: dict[str, Any]) -> ScoreBreakdown:
    categories_raw = data.get("categories", {})
    categories = (
        {str(key): int(value) for key, value in dict(categories_raw).items()}
        if isinstance(categories_raw, dict)
        else {}
    )
    return ScoreBreakdown(categories=categories)


def _parse_visitor_fingerprint_detail(data: dict[str, Any]) -> VisitorFingerprintDetail:
    summary = _parse_visitor_fingerprint_summary(data)
    components_raw = dict(data.get("components", {}))
    activity_raw = dict(data.get("activity", {}))

    sessions = [
        VisitorFingerprintSessionSummary(
            session_id=str(item["session_id"]),
            decision=_parse_decision(dict(item["decision"])),
            request=_parse_request_context(dict(item["request"])),
            score_breakdown=_parse_score_breakdown(dict(item["score_breakdown"])),
        )
        for item in activity_raw.get("sessions", [])
    ]

    return VisitorFingerprintDetail(
        **summary.__dict__,
        components=VisitorFingerprintComponents(
            vector=[int(value) for value in components_raw.get("vector", [])],
        ),
        activity=VisitorFingerprintActivity(sessions=sessions),
    )


def _parse_team(data: dict[str, Any]) -> Team:
    return Team(
        object=str(data["object"]),
        id=str(data["id"]),
        name=str(data["name"]),
        slug=str(data["slug"]),
        status=str(data["status"]),
        created_at=str(data["created_at"]),
        updated_at=data.get("updated_at"),
    )


def _parse_api_key(data: dict[str, Any]) -> ApiKey:
    return ApiKey(
        object=str(data["object"]),
        id=str(data["id"]),
        public_key=str(data["public_key"]),
        name=str(data["name"]),
        environment=str(data["environment"]),
        allowed_origins=[str(value) for value in data.get("allowed_origins", [])]
        if data.get("allowed_origins") is not None
        else None,
        rate_limit=int(data["rate_limit"]) if isinstance(data.get("rate_limit"), int) else None,
        status=str(data["status"]),
        created_at=str(data["created_at"]),
        rotated_at=data.get("rotated_at"),
        revoked_at=data.get("revoked_at"),
    )


def _parse_issued_api_key(data: dict[str, Any]) -> IssuedApiKey:
    api_key = _parse_api_key(data)
    return IssuedApiKey(**api_key.__dict__, secret_key=str(data["secret_key"]))


def _normalize_list(items: list[Any], pagination: dict[str, Any]) -> ListResult[Any]:
    return ListResult(
        items=items,
        limit=int(pagination["limit"]),
        has_more=bool(pagination["has_more"]),
        next_cursor=pagination.get("next_cursor"),
    )


class _BaseAPI:
    def __init__(self, client: "Tripwire") -> None:
        self._client = client


class SessionsAPI(_BaseAPI):
    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        verdict: str | None = None,
        search: str | None = None,
    ) -> ListResult[SessionSummary]:
        response = self._client._request_json(
            "GET",
            "/v1/sessions",
            query=_compact_query(
                {
                    "limit": limit,
                    "cursor": cursor,
                    "verdict": verdict,
                    "search": search,
                }
            ),
        )
        return _normalize_list(
            [_parse_session_summary(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def get(self, session_id: str) -> SessionDetail:
        response = self._client._request_json("GET", f"/v1/sessions/{session_id}")
        return _parse_session_detail(dict(response["data"]))

    def iter(
        self,
        *,
        limit: int | None = None,
        verdict: str | None = None,
        search: str | None = None,
    ) -> Iterator[SessionSummary]:
        cursor: str | None = None
        while True:
            page = self.list(limit=limit, cursor=cursor, verdict=verdict, search=search)
            for item in page.items:
                yield item
            if not page.has_more or not page.next_cursor:
                break
            cursor = page.next_cursor


class FingerprintsAPI(_BaseAPI):
    def list(
        self,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        search: str | None = None,
        sort: str | None = None,
    ) -> ListResult[VisitorFingerprintSummary]:
        response = self._client._request_json(
            "GET",
            "/v1/fingerprints",
            query=_compact_query(
                {
                    "limit": limit,
                    "cursor": cursor,
                    "search": search,
                    "sort": sort,
                }
            ),
        )
        return _normalize_list(
            [_parse_visitor_fingerprint_summary(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def get(self, visitor_id: str) -> VisitorFingerprintDetail:
        response = self._client._request_json("GET", f"/v1/fingerprints/{visitor_id}")
        return _parse_visitor_fingerprint_detail(dict(response["data"]))

    def iter(
        self,
        *,
        limit: int | None = None,
        search: str | None = None,
        sort: str | None = None,
    ) -> Iterator[VisitorFingerprintSummary]:
        cursor: str | None = None
        while True:
            page = self.list(limit=limit, cursor=cursor, search=search, sort=sort)
            for item in page.items:
                yield item
            if not page.has_more or not page.next_cursor:
                break
            cursor = page.next_cursor


class ApiKeysAPI(_BaseAPI):
    def create(
        self,
        team_id: str,
        *,
        name: str | None = None,
        environment: str | None = None,
        allowed_origins: list[str] | None = None,
        rate_limit: int | None = None,
    ) -> IssuedApiKey:
        response = self._client._request_json(
            "POST",
            f"/v1/teams/{team_id}/api-keys",
            body=_compact_query(
                {
                    "name": name,
                    "environment": environment,
                    "allowed_origins": allowed_origins,
                    "rate_limit": rate_limit,
                }
            ),
        )
        return _parse_issued_api_key(dict(response["data"]))

    def list(
        self,
        team_id: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> ListResult[ApiKey]:
        response = self._client._request_json(
            "GET",
            f"/v1/teams/{team_id}/api-keys",
            query=_compact_query({"limit": limit, "cursor": cursor}),
        )
        return _normalize_list(
            [_parse_api_key(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def revoke(self, team_id: str, key_id: str) -> ApiKey:
        response = self._client._request_json(
            "DELETE",
            f"/v1/teams/{team_id}/api-keys/{key_id}",
        )
        return _parse_api_key(dict(response["data"]))

    def rotate(self, team_id: str, key_id: str) -> IssuedApiKey:
        response = self._client._request_json(
            "POST",
            f"/v1/teams/{team_id}/api-keys/{key_id}/rotations",
        )
        return _parse_issued_api_key(dict(response["data"]))


class TeamsAPI(_BaseAPI):
    def __init__(self, client: "Tripwire") -> None:
        super().__init__(client)
        self.api_keys = ApiKeysAPI(client)

    def create(self, *, name: str, slug: str) -> Team:
        response = self._client._request_json(
            "POST",
            "/v1/teams",
            body={"name": name, "slug": slug},
        )
        return _parse_team(dict(response["data"]))

    def get(self, team_id: str) -> Team:
        response = self._client._request_json("GET", f"/v1/teams/{team_id}")
        return _parse_team(dict(response["data"]))

    def update(
        self,
        team_id: str,
        *,
        name: str | None = None,
        status: str | None = None,
    ) -> Team:
        response = self._client._request_json(
            "PATCH",
            f"/v1/teams/{team_id}",
            body=_compact_query({"name": name, "status": status}),
        )
        return _parse_team(dict(response["data"]))


class Tripwire:
    def __init__(
        self,
        *,
        secret_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        resolved_secret = secret_key or os.getenv("TRIPWIRE_SECRET_KEY")
        if not resolved_secret:
            raise TripwireConfigurationError(
                "Missing Tripwire secret key. Pass secret_key explicitly or set TRIPWIRE_SECRET_KEY."
            )

        headers = {
            "Authorization": f"Bearer {resolved_secret}",
            "Accept": "application/json",
            "X-Tripwire-Client": SDK_CLIENT_HEADER,
        }
        if user_agent:
            headers["User-Agent"] = user_agent

        self._client = httpx.Client(
            base_url=base_url or DEFAULT_BASE_URL,
            timeout=timeout,
            transport=transport,
            headers=headers,
        )
        self.sessions = SessionsAPI(self)
        self.fingerprints = FingerprintsAPI(self)
        self.teams = TeamsAPI(self)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Tripwire":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
        expect_content: bool = True,
    ) -> dict[str, Any]:
        response = self._client.request(method, path, params=query, json=body)
        request_id = response.headers.get("x-request-id")

        if response.status_code >= 400:
            payload: dict[str, Any]
            try:
                payload = response.json()
            except ValueError:
                payload = {}

            if isinstance(payload.get("error"), dict):
                error = payload["error"]
                details = error.get("details")
                raise TripwireApiError(
                    status=response.status_code,
                    code=str(error.get("code", "request.failed")),
                    message=str(error.get("message", response.text or response.reason_phrase)),
                    request_id=request_id or error.get("request_id"),
                    field_errors=list(details.get("fields", [])) if isinstance(details, dict) else [],
                    docs_url=error.get("docs_url"),
                    body=payload,
                )

            raise TripwireApiError(
                status=response.status_code,
                code="request.failed",
                message=response.text or response.reason_phrase,
                request_id=request_id,
                body=payload,
            )

        if not expect_content or response.status_code == 204:
            return {}
        return response.json()
