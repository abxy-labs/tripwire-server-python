from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ContractTests(unittest.TestCase):
    @staticmethod
    def _read_spec() -> dict:
        return json.loads((ROOT / "spec" / "openapi.json").read_text())

    def test_only_supported_public_paths_are_exposed(self) -> None:
        spec = self._read_spec()
        self.assertEqual(
            sorted(spec["paths"].keys()),
            [
                "/v1/fingerprints",
                "/v1/fingerprints/{visitorId}",
                "/v1/sessions",
                "/v1/sessions/{sessionId}",
                "/v1/teams",
                "/v1/teams/{teamId}",
                "/v1/teams/{teamId}/api-keys",
                "/v1/teams/{teamId}/api-keys/{keyId}",
                "/v1/teams/{teamId}/api-keys/{keyId}/rotations",
            ],
        )

    def test_collect_endpoints_are_excluded(self) -> None:
        spec = self._read_spec()
        self.assertFalse(any(path.startswith("/v1/collect/") for path in spec["paths"]))

    def test_expected_success_fixtures_exist(self) -> None:
        fixtures = [
            "api/sessions/list.json",
            "api/sessions/detail.json",
            "api/fingerprints/list.json",
            "api/fingerprints/detail.json",
            "api/teams/team.json",
            "api/teams/team-create.json",
            "api/teams/team-update.json",
            "api/teams/api-key-create.json",
            "api/teams/api-key-list.json",
            "api/teams/api-key-rotate.json",
            "api/teams/api-key-revoke.json",
        ]
        for relative_path in fixtures:
            with self.subTest(relative_path=relative_path):
                self.assertTrue((ROOT / "spec" / "fixtures" / relative_path).exists())

    def test_schema_constraints_are_tightened_for_sdk_consumers(self) -> None:
        schemas = self._read_spec()["components"]["schemas"]

        self.assertEqual(schemas["SessionId"]["pattern"], "^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["FingerprintId"]["pattern"], "^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["TeamId"]["pattern"], "^team_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")
        self.assertEqual(schemas["ApiKeyId"]["pattern"], "^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$")

        self.assertEqual(schemas["SessionSummary"]["properties"]["id"], {"$ref": "#/components/schemas/SessionId"})
        self.assertEqual(schemas["Team"]["properties"]["status"], {"$ref": "#/components/schemas/TeamStatus"})
        self.assertEqual(schemas["ApiKey"]["properties"]["status"], {"$ref": "#/components/schemas/ApiKeyStatus"})
        self.assertEqual(
            schemas["PublicError"]["properties"]["code"]["x-tripwire-known-values-ref"],
            "#/components/schemas/KnownPublicErrorCode",
        )
        self.assertEqual(schemas["TeamStatus"]["enum"], ["active", "suspended", "deleted"])
        self.assertEqual(schemas["ApiKeyStatus"]["enum"], ["active", "revoked", "rotated"])
        self.assertTrue(
            {"decision", "highlights", "automation", "web_bot_auth", "network", "runtime_integrity", "visitor_fingerprint", "connection_fingerprint", "previous_decisions", "request", "browser", "device", "analysis_coverage", "signals_fired", "client_telemetry"}.issubset(
                set(schemas["SessionDetail"]["required"])
            )
        )
        self.assertEqual(
            schemas["SessionDetail"]["properties"]["request"],
            {"$ref": "#/components/schemas/SessionDetailRequest"},
        )
        self.assertEqual(
            schemas["SessionDetail"]["properties"]["client_telemetry"],
            {"$ref": "#/components/schemas/SessionClientTelemetry"},
        )
        self.assertEqual(
            schemas["SessionDetail"]["properties"]["automation"],
            {"anyOf": [{"$ref": "#/components/schemas/SessionAutomation"}, {"type": "null"}]},
        )
        self.assertEqual(
            schemas["SessionDetail"]["properties"]["signals_fired"],
            {"type": "array", "items": {"$ref": "#/components/schemas/SessionSignalFired"}},
        )
        self.assertEqual(schemas["SessionSignalFired"]["properties"]["signal"]["type"], "string")
        self.assertTrue(
            {"allowed_origins", "rate_limit", "rotated_at", "revoked_at"}.issubset(set(schemas["ApiKey"]["required"]))
        )
        self.assertNotIn("CollectBatchResponse", schemas)

    def test_public_operations_have_stable_ids_and_tags(self) -> None:
        paths = self._read_spec()["paths"]

        self.assertEqual(paths["/v1/sessions"]["get"]["operationId"], "listSessions")
        self.assertEqual(paths["/v1/sessions"]["get"]["tags"], ["Sessions"])
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["operationId"], "getVisitorFingerprint")
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["tags"], ["Visitor fingerprints"])
        self.assertEqual(paths["/v1/teams/{teamId}"]["patch"]["operationId"], "updateTeam")
        self.assertEqual(paths["/v1/teams/{teamId}"]["patch"]["tags"], ["Teams"])
        self.assertEqual(
            paths["/v1/teams/{teamId}/api-keys/{keyId}/rotations"]["post"]["operationId"],
            "rotateTeamApiKey",
        )
        self.assertEqual(paths["/v1/teams/{teamId}/api-keys/{keyId}/rotations"]["post"]["tags"], ["API Keys"])
