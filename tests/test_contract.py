from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class ContractTests(unittest.TestCase):
    def test_only_supported_public_paths_are_exposed(self) -> None:
        spec = json.loads((ROOT / "spec" / "openapi.json").read_text())
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
        spec = json.loads((ROOT / "spec" / "openapi.json").read_text())
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
