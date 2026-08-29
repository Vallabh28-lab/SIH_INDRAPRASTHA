#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - API Gateway (Phases 2, 4, 5, 6, & 7)
Module: api.py
Description: Asynchronous FastAPI Control Gateway with real-time telemetry ingestion,
             AI threat scoring (Isolation Forest + XGBoost), Explainable AI (XAI SHAP),
             Threat Intelligence enrichment, Forensic Audit Trail (SHA-256),
             and SOC Dashboard polling endpoints.
"""

from datetime import datetime, timezone
import json
import logging
import os
import sys
import threading
import uuid
from typing import Any, Dict, List, Optional


from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from audit_logger import ForensicAuditManager
from flow_schema import FlowRecordSchema
from packet_generator import PacketGenerator
from schemas import (
    JobQueuedResponse,
    JobStatusResponse,
    ProfileRequestSchema,
    TrafficConfigSchema,
)
from threat_detector import ThreatDetectionEngine
from threat_intel import ThreatIntelService
from traffic_profiles import (
    generate_high_velocity_tcp,
    generate_high_volume_udp,
    generate_normal_traffic,
    generate_port_sweep,
)
from xai_explainer import ThreatExplainer
from http_input_parser import parse_http_input, parse_http_target_details
from dns_resolver import resolve_domain, resolve_domain_details
from behavioral_flow_aggregator import generate_behavioral_flow




# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("TrafficGatewayAPI")

app = FastAPI(
    title="NTRO Cyber Threat Detection API & SOC Gateway",
    description="REST API Gateway for traffic simulation, real-time telemetry ingestion, AI threat scoring, XAI explanations, Threat Intel, and Forensic Audit logging.",
    version="2.5.0",
)

# Enable CORS for React SOC Dashboard frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory repositories
jobs_db: Dict[str, Dict[str, Any]] = {}
traffic_history: List[Dict[str, Any]] = []
MAX_HISTORY_SIZE = 500

# Initialize AI / ML, XAI, Threat Intel, and Forensic Audit Manager
try:
    threat_engine = ThreatDetectionEngine()
    logger.info("ThreatDetectionEngine initialized successfully.")
except Exception as exc:
    logger.warning("ThreatDetectionEngine init fallback: %s", exc)
    threat_engine = ThreatDetectionEngine()

try:
    threat_explainer = ThreatExplainer()
    logger.info("ThreatExplainer initialized successfully.")
except Exception as exc:
    logger.warning("ThreatExplainer init fallback: %s", exc)
    threat_explainer = ThreatExplainer()

intel_service = ThreatIntelService()
audit_manager = ForensicAuditManager("logs/audit_trail.json")
FLOWS_LOG_FILE = "logs/flows.jsonl"
flows_file_lock = threading.Lock()
os.makedirs(os.path.dirname(os.path.abspath(FLOWS_LOG_FILE)), exist_ok=True)


def _append_to_flows_store(record: Dict[str, Any]) -> None:
    """Thread-safe append of validated flow telemetry to local operational filestore."""
    try:
        with flows_file_lock:
            with open(FLOWS_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
    except Exception as err:
        logger.error("Failed writing flow record to %s: %s", FLOWS_LOG_FILE, err)



def _execute_custom_traffic_job(job_id: str, config: TrafficConfigSchema) -> None:
    """Worker function executed in the background for custom traffic configurations."""
    jobs_db[job_id]["status"] = "running"
    jobs_db[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("Executing background traffic job [%s] - Custom Config", job_id)

    try:
        generator = PacketGenerator(
            source_ip=config.source_ip,
            destination_ip=config.destination_ip,
            protocol=config.protocol,
            source_port=config.source_port,
            destination_port=config.destination_port,
            packet_count=config.packet_count,
            packet_size=config.packet_size,
            iat=config.iat,
            tcp_flags=config.tcp_flags,
            payload_data=config.payload_data,
        )
        metrics = generator.run()

        jobs_db[job_id]["status"] = "completed"
        jobs_db[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        jobs_db[job_id]["metrics"] = metrics
        logger.info("Background traffic job [%s] COMPLETED successfully.", job_id)

    except Exception as exc:
        logger.error("Background traffic job [%s] FAILED: %s", job_id, exc)
        jobs_db[job_id]["status"] = "failed"
        jobs_db[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        jobs_db[job_id]["error"] = str(exc)


def _execute_profile_traffic_job(job_id: str, request: ProfileRequestSchema) -> None:
    """Worker function executed in the background for pre-configured traffic profiles."""
    jobs_db[job_id]["status"] = "running"
    jobs_db[job_id]["started_at"] = datetime.now(timezone.utc).isoformat()
    logger.info("Executing background traffic job [%s] - Profile '%s'", job_id, request.profile_name)

    try:
        kwargs: Dict[str, Any] = {
            "source_ip": request.source_ip,
            "destination_ip": request.destination_ip,
        }
        if request.packet_count is not None:
            kwargs["packet_count"] = request.packet_count
        if request.iat is not None:
            kwargs["iat"] = request.iat

        if request.profile_name == "normal":
            metrics = generate_normal_traffic(**kwargs)
        elif request.profile_name == "high_velocity_tcp":
            metrics = generate_high_velocity_tcp(**kwargs)
        elif request.profile_name == "port_sweep":
            sweep_kwargs = {
                "source_ip": request.source_ip,
                "destination_ip": request.destination_ip,
            }
            if request.iat is not None:
                sweep_kwargs["iat"] = request.iat
            metrics = generate_port_sweep(**sweep_kwargs)
        elif request.profile_name == "high_volume_udp":
            metrics = generate_high_volume_udp(**kwargs)
        else:
            raise ValueError(f"Unknown traffic profile '{request.profile_name}'")

        jobs_db[job_id]["status"] = "completed"
        jobs_db[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        jobs_db[job_id]["metrics"] = metrics
        logger.info("Background profile job [%s] COMPLETED successfully.", job_id)

    except Exception as exc:
        logger.error("Background profile job [%s] FAILED: %s", job_id, exc)
        jobs_db[job_id]["status"] = "failed"
        jobs_db[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        jobs_db[job_id]["error"] = str(exc)


# =============================================================================
# SYSTEM HEALTH & SOC DASHBOARD ENDPOINTS
# =============================================================================

@app.get("/health", status_code=status.HTTP_200_OK, tags=["System"])
def health_check():
    """Health check endpoint confirming API gateway readiness."""
    return {
        "status": "healthy",
        "service": "traffic-simulator-gateway",
        "version": "2.5.0",
        "active_jobs_count": len(jobs_db),
        "ai_engine_trained": threat_engine.is_trained,
        "audit_records_count": len(audit_manager.audit_records),
    }


@app.post("/api/traffic", status_code=status.HTTP_201_CREATED, tags=["Threat Detection Ingestion"])
def receive_flow_telemetry(flow: FlowRecordSchema):
    """
    Receives aggregated JSON flow records from traffic simulator / daemon,
    evaluates using ML Threat Engine, generates XAI justifications, enriches with Threat Intel,
    persists malicious events to SHA-256 Forensic Audit log, and buffers for SOC Dashboard display.
    """
    try:
        flow_data = flow.model_dump()
        logger.info(
            "[INGEST] Flow record from %s -> %s (%s) | pkts: %d, bytes: %d",
            flow_data["source_ip"],
            flow_data["destination_ip"],
            flow_data["protocol"],
            flow_data["packet_count"],
            flow_data["total_bytes"],
        )

        # 1. AI Threat Detection Engine Evaluation
        prediction_result = threat_engine.predict_flow(flow_data)
        prediction_label = prediction_result.get("prediction", "Normal")
        confidence = float(prediction_result.get("confidence", 0.95))
        anomaly_score = float(prediction_result.get("anomaly_score", 0.10))
        is_malicious = bool(prediction_result.get("is_malicious", prediction_label != "Normal"))

        # 2. Explainable AI (XAI) Justifications
        xai_explanations = threat_explainer.explain_prediction(flow_data)

        # 3. Threat Intelligence Enrichment
        source_intel = intel_service.enrich_ip(flow_data["source_ip"])
        dest_intel = intel_service.enrich_ip(flow_data["destination_ip"])
        combined_intel = {
            "source_ip": source_intel,
            "destination_ip": dest_intel,
        }

        # 4. Forensic SHA-256 Audit Trail Logging (For Malicious Events)
        audit_record = None
        audit_hash = None
        audit_id = None
        if is_malicious:
            audit_record = audit_manager.log_malicious_event(
                event_payload=flow_data,
                prediction=prediction_label,
                confidence=confidence,
                anomaly_score=anomaly_score,
                source_ip=flow_data["source_ip"],
                destination_ip=flow_data["destination_ip"],
                xai_reasons=xai_explanations,
                threat_intel=combined_intel,
            )
            audit_hash = audit_record["audit_hash"]
            audit_id = audit_record["audit_id"]

        now_iso = datetime.now(timezone.utc).isoformat()

        # Build composite SOC event dictionary
        soc_event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": now_iso,
            "prediction": prediction_label,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "is_malicious": is_malicious,
            "source_ip": flow_data["source_ip"],
            "destination_ip": flow_data["destination_ip"],
            "protocol": flow_data["protocol"],
            "source_port": flow_data["source_port"],
            "destination_port": flow_data["destination_port"],
            "packet_count": flow_data["packet_count"],
            "total_bytes": flow_data["total_bytes"],
            "xai_explanations": xai_explanations,
            "threat_intel": combined_intel,
            "audit_hash": audit_hash,
            "audit_id": audit_id,
            "received_flow": flow_data,
        }

        # Buffer into in-memory history list
        traffic_history.insert(0, soc_event)
        if len(traffic_history) > MAX_HISTORY_SIZE:
            traffic_history.pop()

        # Atomically append validated flow record to local operational filestore (logs/flows.jsonl)
        _append_to_flows_store(soc_event)

        return {
            "status": "success",
            "message": "Flow record processed, persisted to flows.jsonl, and audited successfully",
            "prediction": prediction_label,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "is_malicious": is_malicious,
            "xai_explanations": xai_explanations,
            "threat_intel": combined_intel,
            "audit_hash": audit_hash,
            "audit_id": audit_id,
            "received_flow": flow_data,
            "timestamp": now_iso,
        }


    except Exception as e:
        logger.error("[ERROR] Failed to process flow telemetry: %s", str(e), exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/traffic", status_code=status.HTTP_200_OK, tags=["SOC Dashboard"])
def get_traffic_dashboard_data(limit: int = Query(default=100, ge=1, le=500)):
    """
    SOC Dashboard Polling Endpoint:
    Returns recent telemetry events, summary metrics (Total Flows, Threat Count, High Risk Count, Normal Count),
    and time-series visual trend data formatted for Recharts.
    """
    events = traffic_history[:limit]

    # Calculate real-time top-level metric counters
    total_flows = len(traffic_history)
    threats_detected = sum(1 for e in traffic_history if e.get("is_malicious"))
    high_risk_count = sum(1 for e in traffic_history if e.get("anomaly_score", 0) > 0.70 or e.get("confidence", 0) > 0.90 and e.get("is_malicious"))
    normal_count = total_flows - threats_detected

    # Generate visual trend points for Recharts component
    # Group events by minute or simple bucket array
    trends: List[Dict[str, Any]] = []
    bucket_map: Dict[str, Dict[str, int]] = {}

    for event in reversed(traffic_history[:50]):
        time_str = event["timestamp"][11:16]  # HH:MM timestamp substring
        if time_str not in bucket_map:
            bucket_map[time_str] = {"time": time_str, "normal": 0, "malicious": 0, "total": 0}
        bucket_map[time_str]["total"] += 1
        if event["is_malicious"]:
            bucket_map[time_str]["malicious"] += 1
        else:
            bucket_map[time_str]["normal"] += 1

    trends = list(bucket_map.values())

    return {
        "metrics": {
            "total_flows": total_flows,
            "threats_detected": threats_detected,
            "high_risk": high_risk_count,
            "normal_traffic": normal_count,
        },
        "trends": trends,
        "events": events,
    }


@app.get("/api/audit", status_code=status.HTTP_200_OK, tags=["Forensic Audit"])
def get_forensic_audit_logs(limit: int = Query(default=100, ge=1, le=500)):
    """Retrieves SHA-256 tamper-evident forensic audit logs for SOC dashboard drawer."""
    audit_trail = audit_manager.get_audit_trail(limit=limit)
    integrity_check = audit_manager.verify_integrity()
    return {
        "status": "success",
        "integrity": integrity_check,
        "total_audit_records": len(audit_manager.audit_records),
        "audit_logs": audit_trail,
    }


@app.get("/api/metrics", status_code=status.HTTP_200_OK, tags=["SOC Dashboard"])
def get_soc_metrics():
    """Returns top-level metric counters for the SOC dashboard."""
    alerts_file = "logs/alerts.json"
    total_flows = len(traffic_history) if traffic_history else 12450
    threats_detected = sum(1 for e in traffic_history if e.get("is_malicious"))
    high_risk = sum(1 for e in traffic_history if e.get("anomaly_score", 0) > 0.70 or (e.get("confidence", 0) > 0.90 and e.get("is_malicious")))
    
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, "r", encoding="utf-8") as f:
                alerts = [json.loads(line) for line in f if line.strip()]
                if alerts:
                    threats_detected = len(alerts)
                    high_risk = sum(1 for a in alerts if a.get("confidence", 0) > 0.90)
        except Exception:
            pass

    return {
        "total_flows": total_flows,
        "threats_detected": threats_detected,
        "high_risk": high_risk,
        "normal_traffic": max(0, total_flows - threats_detected)
    }


@app.get("/api/incidents", status_code=status.HTTP_200_OK, tags=["SOC Dashboard"])
def get_live_incidents():
    """Returns recent threat incidents and forensic audit logs."""
    alerts_file = "logs/alerts.json"
    if os.path.exists(alerts_file):
        try:
            with open(alerts_file, "r", encoding="utf-8") as f:
                incidents = [json.loads(line) for line in f if line.strip()]
                if incidents:
                    return incidents[-50:]
        except Exception:
            pass
    if audit_manager.audit_records:
        return audit_manager.get_audit_trail(limit=50)
    return [e for e in traffic_history if e.get("is_malicious")][:50]


@app.get("/api/audit/verify", status_code=status.HTTP_200_OK, tags=["Forensic Audit"])
def verify_audit_integrity():
    """Validates full end-to-end cryptographic hash-chain integrity of audit records."""
    return audit_manager.verify_integrity()


@app.post("/api/traffic/simulate", status_code=status.HTTP_200_OK, tags=["SOC Simulator Control"])
def simulate_traffic_event(attack_type: str = Query(default="SYN_Flood")):
    """
    Convenience endpoint for SOC dashboard buttons to inject simulated malicious or normal flows.
    """
    if attack_type == "Normal":
        flow = {
            "source_ip": "192.168.10.45",
            "destination_ip": "192.168.10.1",
            "source_port": 54322,
            "destination_port": 443,
            "protocol": "TCP",
            "packet_count": 45,
            "total_bytes": 22400,
            "flow_duration": 5.2,
            "packets_per_sec": 8.65,
            "bytes_per_sec": 4307.69,
            "mean_packet_size": 497.77,
            "std_packet_size": 320.10,
            "iat_mean": 0.115,
            "iat_std": 0.032,
            "syn_count": 1,
            "ack_count": 35,
        }
    elif attack_type == "SYN_Flood":
        flow = {
            "source_ip": "10.0.4.88",
            "destination_ip": "192.168.10.20",
            "source_port": 49152,
            "destination_port": 80,
            "protocol": "TCP",
            "packet_count": 550,
            "total_bytes": 35200,
            "flow_duration": 0.65,
            "packets_per_sec": 846.15,
            "bytes_per_sec": 54153.84,
            "mean_packet_size": 64.0,
            "std_packet_size": 0.0,
            "iat_mean": 0.0011,
            "iat_std": 0.0003,
            "syn_count": 550,
            "ack_count": 0,
        }
    elif attack_type == "Port_Scan":
        flow = {
            "source_ip": "172.16.5.99",
            "destination_ip": "192.168.10.20",
            "source_port": 59100,
            "destination_port": 22,
            "protocol": "TCP",
            "packet_count": 1,
            "total_bytes": 60,
            "flow_duration": 0.0,
            "packets_per_sec": 10000.0,
            "bytes_per_sec": 600000.0,
            "mean_packet_size": 60.0,
            "std_packet_size": 0.0,
            "iat_mean": 0.0,
            "iat_std": 0.0,
            "syn_count": 1,
            "ack_count": 0,
        }
    else:  # UDP_Flood
        flow = {
            "source_ip": "198.51.100.45",
            "destination_ip": "192.168.10.20",
            "source_port": 44550,
            "destination_port": 9999,
            "protocol": "UDP",
            "packet_count": 1200,
            "total_bytes": 1704000,
            "flow_duration": 1.1,
            "packets_per_sec": 1090.9,
            "bytes_per_sec": 1549090.9,
            "mean_packet_size": 1420.0,
            "std_packet_size": 10.0,
            "iat_mean": 0.0009,
            "iat_std": 0.0002,
            "syn_count": 0,
            "ack_count": 0,
        }

    schema_flow = FlowRecordSchema(**flow)
    return receive_flow_telemetry(schema_flow)


# =============================================================================
# PHASE 2 BACKGROUND TRAFFIC CONTROL ENDPOINTS
# =============================================================================

@app.post(
    "/api/v1/traffic/custom",
    response_model=JobQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Traffic Control"],
)
def trigger_custom_traffic(
    config: TrafficConfigSchema,
    background_tasks: BackgroundTasks,
):
    """Queue a custom Layer 3/4 packet stream generation task asynchronously."""
    job_id = str(uuid.uuid4())
    jobs_db[job_id] = {
        "job_id": job_id,
        "type": "custom",
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "metrics": None,
        "error": None,
        "config": config.model_dump(),
    }

    background_tasks.add_task(_execute_custom_traffic_job, job_id, config)
    logger.info("Queued custom traffic job [%s]", job_id)

    return JobQueuedResponse(
        job_id=job_id,
        status="queued",
        message="Custom traffic generation task queued for background execution.",
    )


@app.post(
    "/api/v1/traffic/profile",
    response_model=JobQueuedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Traffic Control"],
)
def trigger_profile_traffic(
    request: ProfileRequestSchema,
    background_tasks: BackgroundTasks,
):
    """Queue a pre-configured baseline or benchmark profile task asynchronously."""
    job_id = str(uuid.uuid4())
    jobs_db[job_id] = {
        "job_id": job_id,
        "type": "profile",
        "status": "queued",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
        "metrics": None,
        "error": None,
        "profile": request.profile_name,
    }

    background_tasks.add_task(_execute_profile_traffic_job, job_id, request)
    logger.info("Queued profile traffic job [%s] ('%s')", job_id, request.profile_name)

    return JobQueuedResponse(
        job_id=job_id,
        status="queued",
        message=f"Traffic profile '{request.profile_name}' queued for background execution.",
        profile=request.profile_name,
    )


@app.get(
    "/api/v1/traffic/status/{job_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK,
    tags=["Traffic Control"],
)
def get_job_status(job_id: str):
    """Poll the execution status and output telemetry metrics for a background job."""
    if job_id not in jobs_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found.",
        )

    job_data = jobs_db[job_id]
    return JobStatusResponse(
        job_id=job_data["job_id"],
        status=job_data["status"],
        created_at=job_data["created_at"],
        started_at=job_data["started_at"],
        completed_at=job_data["completed_at"],
        metrics=job_data["metrics"],
        error=job_data["error"],
    )


@app.get(
    "/api/v1/traffic/jobs",
    response_model=List[JobStatusResponse],
    status_code=status.HTTP_200_OK,
    tags=["Traffic Control"],
)
def list_jobs():
    """List all recent queued, running, completed, or failed traffic jobs."""
    return [
        JobStatusResponse(
            job_id=v["job_id"],
            status=v["status"],
            created_at=v["created_at"],
            started_at=v["started_at"],
            completed_at=v["completed_at"],
            metrics=v["metrics"],
            error=v["error"],
        )
        for v in jobs_db.values()
    ]


@app.post("/api/parse-target", status_code=status.HTTP_200_OK, tags=["Input Parser"])
def parse_target_endpoint(payload: Dict[str, Any]):
    """
    Accepts target URL, bare domain, or raw HTTP request line,
    and returns parsed host/domain details using http_input_parser.
    """
    raw_input = payload.get("input") or payload.get("raw_input") or payload.get("target") or ""
    if not raw_input:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload must include 'input', 'raw_input', or 'target' field."
        )
    return parse_http_target_details(raw_input)


@app.post("/api/resolve-dns", status_code=status.HTTP_200_OK, tags=["DNS Resolution"])
def resolve_dns_endpoint(payload: Dict[str, Any]):
    """
    Accepts domain, URL, or host string and converts to IPv4 with socket.gaierror fallback.
    """
    domain = payload.get("domain") or payload.get("host") or payload.get("target") or payload.get("input") or ""
    default_ip = payload.get("default_ip", "192.168.10.1")
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload must include 'domain', 'host', or 'target' field."
        )
    return resolve_domain_details(domain, default_ip=default_ip)


@app.post("/api/generate-flow", status_code=status.HTTP_200_OK, tags=["Behavioral Flow Aggregator"])
def generate_behavioral_flow_endpoint(payload: Dict[str, Any]):
    """
    Synthesizes a Pydantic-compliant flow record from target request context,
    dynamically injecting attack parameters if flagged as a security test.
    """
    target = payload.get("target") or payload.get("destination_ip") or payload.get("domain") or "collector.internal"
    traffic_type = payload.get("traffic_type") or payload.get("type") or "normal"
    is_attack = payload.get("is_attack") or payload.get("attack", False)
    port = payload.get("port") or payload.get("destination_port")
    source_ip = payload.get("source_ip")
    
    flow_record = generate_behavioral_flow(
        target_host_or_ip=target,
        source_ip=source_ip,
        traffic_type=traffic_type,
        is_attack=is_attack,
        destination_port=port,
    )
    return flow_record


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)



