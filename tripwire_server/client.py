from __future__ import annotations

import os
from typing import Any, Iterator

import httpx

from .errors import TripwireApiError, TripwireConfigurationError
from .types import (
    ApiKey,
    FingerprintDetail,
    FingerprintReference,
    FingerprintSessionSummary,
    FingerprintSummary,
    IssuedApiKey,
    ListResult,
    ResultSummary,
    SessionDetail,
    SessionLatestResultDetail,
    SessionMetadata,
    SessionSummary,
    Team,
)

DEFAULT_BASE_URL = "https://api.tripwirejs.com"
DEFAULT_TIMEOUT = 30.0
SDK_CLIENT_HEADER = "tripwire-server-python/0.1.0"


def _compact_query(query: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in query.items() if value is not None}


def _parse_result_summary(data: dict[str, Any]) -> ResultSummary:
    return ResultSummary(
        event_id=str(data["eventId"]),
        verdict=str(data["verdict"]),
        risk_score=int(data["riskScore"]),
        phase=data.get("phase"),
        provisional=data.get("provisional"),
        manipulation_score=data.get("manipulationScore"),
        manipulation_verdict=data.get("manipulationVerdict"),
        evaluation_duration=data.get("evaluationDuration"),
        scored_at=str(data["scoredAt"]),
    )


def _parse_fingerprint_reference(data: dict[str, Any] | None) -> FingerprintReference | None:
    if data is None:
        return None
    return FingerprintReference(
        object=str(data["object"]),
        id=str(data["id"]),
        confidence=data.get("confidence"),
        timestamp=data.get("timestamp"),
    )


def _parse_metadata(data: dict[str, Any]) -> SessionMetadata:
    return SessionMetadata(
        user_agent=str(data["userAgent"]),
        url=str(data["url"]),
        screen_size=data.get("screenSize"),
        touch_device=data.get("touchDevice"),
        client_ip=str(data["clientIp"]),
    )


def _parse_session_summary(data: dict[str, Any]) -> SessionSummary:
    return SessionSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("createdAt"),
        latest_event_id=str(data["latestEventId"]),
        latest_result=_parse_result_summary(dict(data["latestResult"])),
        fingerprint=_parse_fingerprint_reference(data.get("fingerprint")),
        last_scored_at=str(data["lastScoredAt"]),
    )


def _parse_session_detail(data: dict[str, Any]) -> SessionDetail:
    latest = dict(data["latestResult"])
    latest_result = SessionLatestResultDetail(
        **_parse_result_summary(latest).__dict__,
        visitor_id=latest.get("visitorId"),
        metadata=_parse_metadata(dict(latest["metadata"])),
    )
    return SessionDetail(
        object=str(data["object"]),
        id=str(data["id"]),
        created_at=data.get("createdAt"),
        latest_event_id=str(data["latestEventId"]),
        latest_result=latest_result,
        ip_intel=data.get("ipIntel"),
        fingerprint=_parse_fingerprint_reference(data.get("fingerprint")),
        result_history=[_parse_result_summary(dict(item)) for item in data.get("resultHistory", [])],
    )


def _parse_fingerprint_summary(data: dict[str, Any]) -> FingerprintSummary:
    return FingerprintSummary(
        object=str(data["object"]),
        id=str(data["id"]),
        first_seen_at=str(data["firstSeenAt"]),
        last_seen_at=str(data["lastSeenAt"]),
        seen_count=int(data["seenCount"]),
        last_user_agent=str(data["lastUserAgent"]),
        last_ip=str(data["lastIp"]),
        expires_at=str(data["expiresAt"]),
        anchor_webgl_hash=data.get("anchorWebglHash"),
        anchor_params_hash=data.get("anchorParamsHash"),
        anchor_audio_hash=data.get("anchorAudioHash"),
        fingerprint_vector=[int(value) for value in data.get("fingerprintVector", [])],
        has_cookie=bool(data.get("hasCookie", False)),
        has_ls=bool(data.get("hasLs", False)),
        has_idb=bool(data.get("hasIdb", False)),
        has_sw=bool(data.get("hasSw", False)),
        has_wn=bool(data.get("hasWn", False)),
    )


def _parse_fingerprint_detail(data: dict[str, Any]) -> FingerprintDetail:
    summary = _parse_fingerprint_summary(data)
    sessions = [
        FingerprintSessionSummary(
            event_id=str(item["eventId"]),
            verdict=str(item["verdict"]),
            risk_score=int(item["riskScore"]),
            scored_at=str(item["scoredAt"]),
            user_agent=str(item["userAgent"]),
            url=str(item["url"]),
            client_ip=str(item["clientIp"]),
            screen_size=item.get("screenSize"),
            category_scores={str(key): int(value) for key, value in dict(item["categoryScores"]).items()}
            if isinstance(item.get("categoryScores"), dict)
            else None,
        )
        for item in data.get("sessions", [])
    ]
    return FingerprintDetail(**summary.__dict__, sessions=sessions)


def _parse_team(data: dict[str, Any]) -> Team:
    return Team(
        object=str(data["object"]),
        id=str(data["id"]),
        name=str(data["name"]),
        slug=str(data["slug"]),
        status=str(data["status"]),
        created_at=str(data["createdAt"]),
        updated_at=data.get("updatedAt"),
    )


def _parse_api_key(data: dict[str, Any]) -> ApiKey:
    return ApiKey(
        object=str(data["object"]),
        id=str(data["id"]),
        key=str(data["key"]),
        name=str(data["name"]),
        is_test=bool(data["isTest"]),
        allowed_origins=[str(value) for value in data.get("allowedOrigins", [])] if data.get("allowedOrigins") is not None else None,
        rate_limit=data.get("rateLimit"),
        status=str(data["status"]),
        created_at=str(data["createdAt"]),
        rotated_at=data.get("rotatedAt"),
        revoked_at=data.get("revokedAt"),
    )


def _parse_issued_api_key(data: dict[str, Any]) -> IssuedApiKey:
    api_key = _parse_api_key(data)
    return IssuedApiKey(**api_key.__dict__, secret_key=str(data["secretKey"]))


def _normalize_list(items: list[Any], pagination: dict[str, Any]) -> ListResult[Any]:
    return ListResult(
        items=items,
        limit=int(pagination["limit"]),
        has_more=bool(pagination["hasMore"]),
        next_cursor=pagination.get("nextCursor"),
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
    ) -> ListResult[FingerprintSummary]:
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
            [_parse_fingerprint_summary(dict(item)) for item in response["data"]],
            dict(response["pagination"]),
        )

    def get(self, visitor_id: str) -> FingerprintDetail:
        response = self._client._request_json("GET", f"/v1/fingerprints/{visitor_id}")
        return _parse_fingerprint_detail(dict(response["data"]))

    def iter(
        self,
        *,
        limit: int | None = None,
        search: str | None = None,
        sort: str | None = None,
    ) -> Iterator[FingerprintSummary]:
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
        is_test: bool | None = None,
        allowed_origins: list[str] | None = None,
        rate_limit: int | None = None,
    ) -> IssuedApiKey:
        response = self._client._request_json(
            "POST",
            f"/v1/teams/{team_id}/api-keys",
            body=_compact_query(
                {
                    "name": name,
                    "isTest": is_test,
                    "allowedOrigins": allowed_origins,
                    "rateLimit": rate_limit,
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

    def revoke(self, team_id: str, key_id: str) -> None:
        self._client._request_json(
            "DELETE",
            f"/v1/teams/{team_id}/api-keys/{key_id}",
            expect_content=False,
        )

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
            base_url=base_url,
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
                    request_id=request_id or error.get("requestId"),
                    field_errors=list(details.get("fieldErrors", [])) if isinstance(details, dict) else [],
                    docs_url=error.get("docsUrl"),
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
