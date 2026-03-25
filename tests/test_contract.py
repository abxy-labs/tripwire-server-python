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
            "public-api/sessions/list.json",
            "public-api/sessions/detail.json",
            "public-api/fingerprints/list.json",
            "public-api/fingerprints/detail.json",
            "public-api/teams/team.json",
            "public-api/teams/team-create.json",
            "public-api/teams/team-update.json",
            "public-api/teams/api-key-create.json",
            "public-api/teams/api-key-list.json",
            "public-api/teams/api-key-rotate.json",
            "public-api/teams/api-key-revoke.json",
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
        self.assertIn("ipIntel", schemas["SessionDetail"]["required"])
        self.assertTrue(
            {"allowedOrigins", "rateLimit", "rotatedAt", "revokedAt"}.issubset(set(schemas["ApiKey"]["required"]))
        )
        self.assertNotIn("CollectBatchResponse", schemas)

    def test_public_operations_have_stable_ids_and_tags(self) -> None:
        paths = self._read_spec()["paths"]

        self.assertEqual(paths["/v1/sessions"]["get"]["operationId"], "listSessions")
        self.assertEqual(paths["/v1/sessions"]["get"]["tags"], ["Sessions"])
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["operationId"], "getFingerprint")
        self.assertEqual(paths["/v1/fingerprints/{visitorId}"]["get"]["tags"], ["Fingerprints"])
        self.assertEqual(paths["/v1/teams/{teamId}"]["patch"]["operationId"], "updateTeam")
        self.assertEqual(paths["/v1/teams/{teamId}"]["patch"]["tags"], ["Teams"])
        self.assertEqual(
            paths["/v1/teams/{teamId}/api-keys/{keyId}/rotations"]["post"]["operationId"],
            "rotateTeamApiKey",
        )
        self.assertEqual(paths["/v1/teams/{teamId}/api-keys/{keyId}/rotations"]["post"]["tags"], ["API Keys"])
