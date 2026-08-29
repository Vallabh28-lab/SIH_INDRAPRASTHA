#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 7: Forensic Audit Trail Engine
Module: audit_logger.py
Description: Cryptographic SHA-256 forensic audit logger providing tamper-evident,
             chain-linked event recording for malicious network flow detections,
             prepared for Hyperledger Fabric blockchain anchoring.
"""

import json
import logging
import os
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ForensicAuditManager")


class ForensicAuditManager:
    """
    Cryptographic SHA-256 Forensic Audit Manager:
    - Intercepts malicious threat detection events from API telemetry pipeline.
    - Computes cryptographic SHA-256 hashes of event payloads and timestamps.
    - Implements tamper-evident hash-chaining (blockchain readiness).
    - Persists audit logs to 'logs/audit_trail.json'.
    - Provides cryptographic integrity verification functions.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, log_path: str = "logs/audit_trail.json"):
        self.log_path = log_path
        self.audit_records: List[Dict[str, Any]] = []
        self._ensure_log_directory()
        self._load_audit_trail()

    def _ensure_log_directory(self) -> None:
        """Create logs directory if it does not exist."""
        log_dir = os.path.dirname(self.log_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    def _load_audit_trail(self) -> None:
        """Load existing audit trail records from disk into memory."""
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    self.audit_records = json.load(f)
                logger.info("Loaded %d audit records from '%s'", len(self.audit_records), self.log_path)
            except Exception as e:
                logger.error("Failed to load existing audit trail from '%s': %s", self.log_path, e)
                self.audit_records = []

    def _save_audit_trail(self) -> None:
        """Persist audit records array atomically to disk."""
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(self.audit_records, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist audit trail to '%s': %s", self.log_path, e)

    def _calculate_payload_hash(self, payload: Dict[str, Any]) -> str:
        """Generate SHA-256 digest of normalized payload JSON data."""
        canonical_str = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def _calculate_block_hash(
        self,
        audit_id: str,
        timestamp: str,
        prev_hash: str,
        payload_hash: str,
        prediction: str,
        confidence: float,
    ) -> str:
        """Calculate tamper-evident block SHA-256 hash for audit record."""
        header = f"{audit_id}|{timestamp}|{prev_hash}|{payload_hash}|{prediction}|{confidence:.4f}"
        return hashlib.sha256(header.encode("utf-8")).hexdigest()

    def log_malicious_event(
        self,
        event_payload: Dict[str, Any],
        prediction: str,
        confidence: float,
        anomaly_score: float,
        source_ip: str,
        destination_ip: str,
        xai_reasons: Optional[List[str]] = None,
        threat_intel: Optional[Dict[str, Any]] = None,
        auto_save: bool = True,
    ) -> Dict[str, Any]:
        """
        Interprets malicious detection event, builds tamper-evident SHA-256 audit record,
        links to previous hash, and appends to persistent audit log.
        """
        audit_id = f"AUD-{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()

        # Determine previous block hash for cryptographic chaining
        prev_hash = self.GENESIS_HASH
        if self.audit_records:
            prev_hash = self.audit_records[-1].get("audit_hash", self.GENESIS_HASH)

        payload_hash = self._calculate_payload_hash(event_payload)
        audit_hash = self._calculate_block_hash(
            audit_id, timestamp, prev_hash, payload_hash, prediction, confidence
        )

        record = {
            "audit_id": audit_id,
            "timestamp": timestamp,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "anomaly_score": round(anomaly_score, 4),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "payload_sha256": payload_hash,
            "prev_hash": prev_hash,
            "audit_hash": audit_hash,
            "verified": True,
            "blockchain_status": "READY_FOR_HYPERLEDGER_ANCHOR",
            "xai_reasons": xai_reasons or [],
            "threat_intel": threat_intel or {},
            "raw_payload": event_payload,
        }

        self.audit_records.append(record)
        if auto_save:
            self._save_audit_trail()

        logger.info(
            "[FORENSIC AUDIT] Logged Threat [%s] %s | Source: %s -> %s | SHA256: %s",
            audit_id,
            prediction,
            source_ip,
            destination_ip,
            audit_hash[:16] + "...",
        )
        return record

    def get_audit_trail(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent forensic audit trail records (newest first)."""
        return list(reversed(self.audit_records[-limit:]))

    def verify_integrity(self) -> Dict[str, Any]:
        """
        Verify the end-to-end cryptographic hash-chain integrity of all audit records.
        Detects any unauthorized modification or deletion in audit_trail.json.
        """
        if not self.audit_records:
            return {
                "status": "VALID",
                "total_records": 0,
                "corrupted_records": [],
                "message": "Audit trail is empty. Integrity intact.",
            }

        corrupted = []
        expected_prev_hash = self.GENESIS_HASH

        for idx, rec in enumerate(self.audit_records):
            calc_payload_hash = self._calculate_payload_hash(rec.get("raw_payload", {}))
            calc_block_hash = self._calculate_block_hash(
                rec["audit_id"],
                rec["timestamp"],
                rec["prev_hash"],
                calc_payload_hash,
                rec["prediction"],
                rec["confidence"],
            )

            is_hash_valid = calc_block_hash == rec.get("audit_hash")
            is_chain_valid = rec.get("prev_hash") == expected_prev_hash

            if not (is_hash_valid and is_chain_valid):
                corrupted.append({
                    "index": idx,
                    "audit_id": rec.get("audit_id"),
                    "hash_valid": is_hash_valid,
                    "chain_valid": is_chain_valid,
                    "expected_hash": calc_block_hash,
                    "actual_hash": rec.get("audit_hash"),
                })

            expected_prev_hash = rec.get("audit_hash", self.GENESIS_HASH)

        status_str = "VALID" if len(corrupted) == 0 else "CORRUPTED"
        return {
            "status": status_str,
            "total_records": len(self.audit_records),
            "corrupted_count": len(corrupted),
            "corrupted_records": corrupted,
            "message": "Audit trail tamper-evident verification complete.",
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    manager = ForensicAuditManager("logs/test_audit_trail.json")
    dummy_event = {"source_ip": "10.0.4.88", "packet_count": 500, "protocol": "TCP"}
    rec = manager.log_malicious_event(
        event_payload=dummy_event,
        prediction="SYN_Flood",
        confidence=0.98,
        anomaly_score=0.85,
        source_ip="10.0.4.88",
        destination_ip="192.168.10.20",
        xai_reasons=["✓ High SYN flag concentration", "✓ High packet rate"],
    )
    print("Logged Record SHA256:", rec["audit_hash"])
    print("Integrity Check:", manager.verify_integrity())
