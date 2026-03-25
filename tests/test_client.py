from __future__ import annotations

import os
import unittest

import httpx

from tests.test_helpers import load_fixture
from tripwire_server import Tripwire
from tripwire_server.errors import TripwireApiError, TripwireConfigurationError


def json_response(
    body: object,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers={"content-type": "application/json", **(headers or {})},
        json=body,
    )


class ClientTests(unittest.TestCase):
    def test_env_secret_fallback(self) -> None:
        original = os.environ.get("TRIPWIRE_SECRET_KEY")
        os.environ["TRIPWIRE_SECRET_KEY"] = "sk_env_default"
        fixture = load_fixture("public-api/sessions/list.json")

        transport = httpx.MockTransport(lambda _request: json_response(fixture))
        try:
            client = Tripwire(transport=transport)
            result = client.sessions.list()
            self.assertEqual(len(result.items), 1)
        finally:
            client.close()
            if original is None:
                os.environ.pop("TRIPWIRE_SECRET_KEY", None)
            else:
                os.environ["TRIPWIRE_SECRET_KEY"] = original

    def test_missing_secret_raises(self) -> None:
        original = os.environ.pop("TRIPWIRE_SECRET_KEY", None)
        try:
            with self.assertRaises(TripwireConfigurationError):
                Tripwire()
        finally:
            if original is not None:
                os.environ["TRIPWIRE_SECRET_KEY"] = original

    def test_base_url_timeout_and_headers_are_applied(self) -> None:
        fixture = load_fixture("public-api/sessions/list.json")

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(str(request.url), "https://example.tripwire.dev/v1/sessions?limit=5")
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            self.assertEqual(request.headers["X-Tripwire-Client"], "tripwire-server-python/0.1.0")
            self.assertEqual(request.headers["User-Agent"], "custom-tripwire-client")
            return json_response(fixture)

        client = Tripwire(
            secret_key="sk_live_test",
            base_url="https://example.tripwire.dev",
            timeout=5.0,
            user_agent="custom-tripwire-client",
            transport=httpx.MockTransport(handler),
        )
        try:
            client.sessions.list(limit=5)
            self.assertEqual(client._client.timeout.connect, 5.0)
        finally:
            client.close()

    def test_sessions_list_and_iter(self) -> None:
        first_page = load_fixture("public-api/sessions/list.json")
        second_page = {
            "data": [
                {
                    **first_page["data"][0],
                    "id": "sid_example_two",
                    "latestEventId": "evt_example_two",
                    "lastScoredAt": "2026-03-24T20:01:05.000Z",
                }
            ],
            "pagination": {
                "limit": 50,
                "hasMore": False,
            },
        }

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.headers["Authorization"], "Bearer sk_live_test")
            cursor = request.url.params.get("cursor")
            return json_response(second_page if cursor else first_page)

        client = Tripwire(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            page = client.sessions.list(verdict="bot", limit=25)
            self.assertEqual(page.limit, 50)
            self.assertTrue(page.has_more)
            self.assertEqual(page.next_cursor, "cur_sessions_page_2")
            self.assertEqual(
                [item.id for item in client.sessions.iter(verdict="human")],
                ["sid_example_one", "sid_example_two"],
            )
        finally:
            client.close()

    def test_session_detail_and_fingerprint_endpoints(self) -> None:
        session_fixture = load_fixture("public-api/sessions/detail.json")
        fp_list_fixture = load_fixture("public-api/fingerprints/list.json")
        fp_detail_fixture = load_fixture("public-api/fingerprints/detail.json")

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/v1/sessions/sid_example_one"):
                return json_response(session_fixture)
            if path.endswith("/v1/fingerprints/vis_example_one"):
                return json_response(fp_detail_fixture)
            return json_response(fp_list_fixture)

        client = Tripwire(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            session = client.sessions.get("sid_example_one")
            self.assertEqual(session.id, "sid_example_one")
            fp_page = client.fingerprints.list()
            self.assertEqual(fp_page.items[0].id, "vis_example_one")
            fp_detail = client.fingerprints.get("vis_example_one")
            self.assertEqual(fp_detail.id, "vis_example_one")
        finally:
            client.close()

    def test_teams_and_api_keys(self) -> None:
        team_fixture = load_fixture("public-api/teams/team.json")
        team_create_fixture = load_fixture("public-api/teams/team-create.json")
        team_update_fixture = load_fixture("public-api/teams/team-update.json")
        key_create_fixture = load_fixture("public-api/teams/api-key-create.json")
        key_list_fixture = load_fixture("public-api/teams/api-key-list.json")
        key_rotate_fixture = load_fixture("public-api/teams/api-key-rotate.json")

        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            method = request.method
            if path.endswith("/v1/teams") and method == "POST":
                return json_response(team_create_fixture, status_code=201)
            if path.endswith("/v1/teams/team_example") and method == "PATCH":
                return json_response(team_update_fixture)
            if path.endswith("/v1/teams/team_example") and method == "GET":
                return json_response(team_fixture)
            if path.endswith("/v1/teams/team_example/api-keys/key_example/rotations"):
                return json_response(key_rotate_fixture, status_code=201)
            if path.endswith("/v1/teams/team_example/api-keys/key_example"):
                return httpx.Response(status_code=204)
            if path.endswith("/v1/teams/team_example/api-keys") and method == "POST":
                return json_response(key_create_fixture, status_code=201)
            if path.endswith("/v1/teams/team_example/api-keys"):
                return json_response(key_list_fixture)
            raise AssertionError(f"Unexpected request: {method} {path}")

        client = Tripwire(secret_key="sk_live_test", transport=httpx.MockTransport(handler))
        try:
            self.assertEqual(client.teams.get("team_example").id, "team_example")
            self.assertEqual(
                client.teams.create(name="Example Team", slug="example-team").updated_at,
                "2026-03-24T19:00:00.000Z",
            )
            self.assertEqual(
                client.teams.update("team_example", name="Updated Example Team").name,
                "Updated Example Team",
            )
            self.assertEqual(
                client.teams.api_keys.create("team_example", name="Production").secret_key,
                "sk_live_example",
            )
            self.assertEqual(client.teams.api_keys.list("team_example").items[0].id, "key_example")
            client.teams.api_keys.revoke("team_example", "key_example")
            self.assertEqual(
                client.teams.api_keys.rotate("team_example", "key_example").secret_key,
                "sk_live_rotated",
            )
        finally:
            client.close()

    def test_validation_errors_are_parsed(self) -> None:
        fixture = load_fixture("errors/validation-error.json")
        self._assert_api_error_fixture(fixture, expected_field_errors=True)

    def test_auth_and_not_found_errors_are_parsed(self) -> None:
        for name in ("errors/missing-api-key.json", "errors/invalid-api-key.json", "errors/not-found.json"):
            with self.subTest(name=name):
                self._assert_api_error_fixture(load_fixture(name))

    def _assert_api_error_fixture(
        self,
        fixture: dict[str, object],
        *,
        expected_field_errors: bool = False,
    ) -> None:
        error = fixture["error"]
        assert isinstance(error, dict)
        client = Tripwire(
            secret_key="sk_live_test",
            transport=httpx.MockTransport(
                lambda _request: json_response(
                    fixture,
                    status_code=int(error["status"]),
                    headers={"x-request-id": str(error["requestId"])},
                )
            ),
        )
        try:
            with self.assertRaises(TripwireApiError) as exc:
                client.sessions.list(limit=999)
            self.assertEqual(exc.exception.code, error["code"])
            self.assertEqual(exc.exception.request_id, error["requestId"])
            self.assertEqual(exc.exception.docs_url, error["docsUrl"])
            self.assertEqual(bool(exc.exception.field_errors), expected_field_errors)
        finally:
            client.close()
