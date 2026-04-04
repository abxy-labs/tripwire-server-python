from __future__ import annotations

import json
import unittest
from pathlib import Path

from tripwire_server import (
    create_delivery_key_pair,
    create_gate_approved_webhook_response,
    decrypt_gate_delivery_envelope,
    derive_gate_agent_token_env_key,
    import_delivery_private_key_pkcs8,
    is_blocked_gate_env_var_key,
    is_gate_managed_env_var_key,
    validate_gate_approved_webhook_payload,
    validate_gate_delivery_request,
    verify_gate_webhook_signature,
)

ROOT = Path(__file__).resolve().parent.parent


class GateDeliveryTests(unittest.TestCase):
    def test_delivery_request_and_vector_fixtures(self) -> None:
        delivery_request_fixture = json.loads((ROOT / "spec" / "fixtures" / "gate-delivery" / "delivery-request.json").read_text())
        vector_fixture = json.loads((ROOT / "spec" / "fixtures" / "gate-delivery" / "vector.v1.json").read_text())

        validated = validate_gate_delivery_request(delivery_request_fixture["delivery"])
        self.assertEqual(validated.key_id, delivery_request_fixture["derived_key_id"])

        private_key = import_delivery_private_key_pkcs8(vector_fixture["private_key_pkcs8"])
        decrypted = decrypt_gate_delivery_envelope(private_key, vector_fixture["envelope"])
        self.assertEqual(decrypted.version, vector_fixture["payload"]["version"])
        self.assertEqual(decrypted.outputs, vector_fixture["payload"]["outputs"])
        self.assertEqual(decrypted.ack_token, vector_fixture["payload"]["ack_token"])

    def test_webhook_payload_signature_and_env_policy_fixtures(self) -> None:
        payload_fixture = json.loads((ROOT / "spec" / "fixtures" / "gate-delivery" / "approved-webhook-payload.valid.json").read_text())
        signature_fixture = json.loads((ROOT / "spec" / "fixtures" / "gate-delivery" / "webhook-signature.json").read_text())
        env_policy_fixture = json.loads((ROOT / "spec" / "fixtures" / "gate-delivery" / "env-policy.json").read_text())

        validated = validate_gate_approved_webhook_payload(payload_fixture)
        self.assertEqual(validated.service_id, payload_fixture["service_id"])
        self.assertEqual(validated.gate_session_id, payload_fixture["gate_session_id"])

        self.assertTrue(
            verify_gate_webhook_signature(
                secret=signature_fixture["secret"],
                timestamp=signature_fixture["timestamp"],
                raw_body=signature_fixture["raw_body"],
                signature=signature_fixture["signature"],
                now_seconds=signature_fixture["now_seconds"],
            )
        )
        self.assertFalse(
            verify_gate_webhook_signature(
                secret=signature_fixture["secret"],
                timestamp=signature_fixture["timestamp"],
                raw_body=signature_fixture["raw_body"],
                signature=signature_fixture["invalid_signature"],
                now_seconds=signature_fixture["now_seconds"],
            )
        )
        self.assertFalse(
            verify_gate_webhook_signature(
                secret=signature_fixture["secret"],
                timestamp=signature_fixture["expired_timestamp"],
                raw_body=signature_fixture["raw_body"],
                signature=signature_fixture["signature"],
                now_seconds=signature_fixture["now_seconds"],
            )
        )

        for entry in env_policy_fixture["derive_agent_token_env_key"]:
            self.assertEqual(derive_gate_agent_token_env_key(entry["service_id"]), entry["expected"])
        for entry in env_policy_fixture["is_gate_managed_env_var_key"]:
            self.assertEqual(is_gate_managed_env_var_key(entry["key"]), entry["managed"])
        for entry in env_policy_fixture["is_blocked_gate_env_var_key"]:
            self.assertEqual(is_blocked_gate_env_var_key(entry["key"]), entry["blocked"])

    def test_created_response_roundtrips(self) -> None:
        key_pair = create_delivery_key_pair()
        response = create_gate_approved_webhook_response(
            {
                "delivery": key_pair.delivery,
                "outputs": {
                    "TRIPWIRE_PUBLISHABLE_KEY": "pk_live_bundle",
                    "TRIPWIRE_SECRET_KEY": "sk_live_bundle",
                },
            }
        )
        decrypted = decrypt_gate_delivery_envelope(key_pair.private_key, response.encrypted_delivery)
        self.assertEqual(
            decrypted.outputs,
            {
                "TRIPWIRE_PUBLISHABLE_KEY": "pk_live_bundle",
                "TRIPWIRE_SECRET_KEY": "sk_live_bundle",
            },
        )


if __name__ == "__main__":
    unittest.main()
