from __future__ import annotations

import base64
import hashlib
import json
import os
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import TripwireConfigurationError, TripwireTokenVerificationError
from .types import SessionMetadata, VerificationResult, VerifiedTripwireSignal, VerifiedTripwireToken

VERSION = 0x01


def _resolve_secret(secret_key: str | None) -> str:
    resolved = secret_key or os.getenv("TRIPWIRE_SECRET_KEY")
    if not resolved:
        raise TripwireConfigurationError(
            "Missing Tripwire secret key. Pass secret_key explicitly or set TRIPWIRE_SECRET_KEY."
        )
    return resolved


def _normalize_secret(secret_key_or_hash: str) -> str:
    if len(secret_key_or_hash) == 64 and all(char in "0123456789abcdefABCDEF" for char in secret_key_or_hash):
        return secret_key_or_hash.lower()
    return hashlib.sha256(secret_key_or_hash.encode("utf-8")).hexdigest()


def _derive_key(secret_key_or_hash: str) -> bytes:
    material = f"{_normalize_secret(secret_key_or_hash)}\0sealed-results".encode("utf-8")
    return hashlib.sha256(material).digest()


def _build_verified_token(payload: dict[str, object]) -> VerifiedTripwireToken:
    metadata_raw = payload.get("metadata")
    if not isinstance(metadata_raw, dict):
        raise TripwireTokenVerificationError("Tripwire token metadata payload is invalid.")

    metadata = SessionMetadata(
        user_agent=str(metadata_raw.get("userAgent", "")),
        url=str(metadata_raw.get("url", "")),
        screen_size=metadata_raw.get("screenSize") if isinstance(metadata_raw.get("screenSize"), str) or metadata_raw.get("screenSize") is None else None,
        touch_device=metadata_raw.get("touchDevice") if isinstance(metadata_raw.get("touchDevice"), bool) or metadata_raw.get("touchDevice") is None else None,
        client_ip=str(metadata_raw.get("clientIp", "")),
    )

    signals: list[VerifiedTripwireSignal] = []
    for signal_raw in payload.get("signals", []):
        if not isinstance(signal_raw, dict):
            continue
        signals.append(
            VerifiedTripwireSignal(
                id=str(signal_raw.get("id", "")),
                category=str(signal_raw.get("category", "")),
                confidence=str(signal_raw.get("confidence", "")),
                score=int(signal_raw.get("score", 0)),
                raw=dict(signal_raw),
            )
        )

    category_scores_raw = payload.get("categoryScores", {})
    category_scores = (
        {str(key): int(value) for key, value in dict(category_scores_raw).items()}
        if isinstance(category_scores_raw, dict)
        else {}
    )

    return VerifiedTripwireToken(
        event_id=str(payload.get("eventId", "")),
        session_id=str(payload.get("sessionId", "")),
        verdict=str(payload.get("verdict", "")),
        score=int(payload.get("score", 0)),
        manipulation_score=int(payload["manipulationScore"]) if isinstance(payload.get("manipulationScore"), int) else None,
        manipulation_verdict=payload.get("manipulationVerdict") if isinstance(payload.get("manipulationVerdict"), str) or payload.get("manipulationVerdict") is None else None,
        evaluation_duration=int(payload["evaluationDuration"]) if isinstance(payload.get("evaluationDuration"), int) else None,
        scored_at=int(payload.get("scoredAt", 0)),
        metadata=metadata,
        signals=signals,
        category_scores=category_scores,
        bot_attribution=dict(payload["botAttribution"]) if isinstance(payload.get("botAttribution"), dict) else None,
        visitor_id=payload.get("visitorId") if isinstance(payload.get("visitorId"), str) or payload.get("visitorId") is None else None,
        visitor_id_confidence=int(payload["visitorIdConfidence"]) if isinstance(payload.get("visitorIdConfidence"), int) else None,
        embed_context=dict(payload["embedContext"]) if isinstance(payload.get("embedContext"), dict) else None,
        phase=payload.get("phase") if isinstance(payload.get("phase"), str) or payload.get("phase") is None else None,
        provisional=payload.get("provisional") if isinstance(payload.get("provisional"), bool) or payload.get("provisional") is None else None,
        raw=dict(payload),
    )


def verify_tripwire_token(sealed_token: str, secret_key: str | None = None) -> VerifiedTripwireToken:
    try:
        resolved_secret = _resolve_secret(secret_key)
        raw = base64.b64decode(sealed_token)
        if len(raw) < 29:
            raise TripwireTokenVerificationError("Tripwire token is too short.")

        version = raw[0]
        if version != VERSION:
            raise TripwireTokenVerificationError(f"Unsupported Tripwire token version: {version}")

        nonce = raw[1:13]
        ciphertext = raw[13:-16]
        tag = raw[-16:]

        decryptor = Cipher(
            algorithms.AES(_derive_key(resolved_secret)),
            modes.GCM(nonce, tag),
        ).decryptor()
        compressed = decryptor.update(ciphertext) + decryptor.finalize()
        payload = json.loads(zlib.decompress(compressed).decode("utf-8"))
        if not isinstance(payload, dict):
            raise TripwireTokenVerificationError("Tripwire token payload is invalid.")
        return _build_verified_token(payload)
    except (TripwireConfigurationError, TripwireTokenVerificationError):
        raise
    except Exception as error:  # noqa: BLE001
        raise TripwireTokenVerificationError("Failed to verify Tripwire token.") from error


def safe_verify_tripwire_token(
    sealed_token: str,
    secret_key: str | None = None,
) -> VerificationResult:
    try:
        return VerificationResult(ok=True, data=verify_tripwire_token(sealed_token, secret_key))
    except (TripwireConfigurationError, TripwireTokenVerificationError) as error:
        return VerificationResult(ok=False, error=error)
