import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from etl_pipeline import extract, transform, load
from l7_inspector import inspect_http_payload

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "traffic_logs.json")

app = FastAPI(
    title="NTRO ETL Pipeline Service",
    description="Extract → Transform (L7 Inspection) → Load (MongoDB Atlas) pipeline trigger.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store of the last run result for /results polling
_last_run: dict = {}


@app.get("/health")
def health():
    """Railway health check — confirms the service is live."""
    return {
        "status": "ok",
        "service": "ntro-etl-pipeline",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/run")
def run_etl():
    """
    Trigger the full ETL pipeline:
      1. Extract  — reads data/traffic_logs.json
      2. Transform — cleans fields + runs L7 signature inspection
      3. Load     — writes enriched records to MongoDB Atlas
    """
    global _last_run
    try:
        df = transform(extract(DATA_FILE))
        load(df)

        l7_hits = int(df["is_l7_malicious"].sum())
        threat_breakdown = (
            df[df["is_l7_malicious"]]["l7_threat_type"]
            .value_counts()
            .to_dict()
        )

        _last_run = {
            "status": "success",
            "records_processed": len(df),
            "l7_threats_detected": l7_hits,
            "threat_breakdown": threat_breakdown,
            "ran_at": datetime.now(timezone.utc).isoformat(),
        }
        return _last_run

    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/results")
def get_last_results():
    """Returns the result of the most recent /run call."""
    if not _last_run:
        return {"status": "no_run_yet", "message": "POST /run to trigger the pipeline."}
    return _last_run


# ---------------------------------------------------------------------------
# /api/traffic  — L7 threat detection endpoint consumed by ntro-dashboard
# ---------------------------------------------------------------------------

class TrafficFlow(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str = "TCP"
    packet_count: int
    total_bytes: int
    uri_path: Optional[str] = None
    body_payload: Optional[str] = None
    http_headers: Optional[dict] = None


@app.post("/api/traffic", status_code=201)
def analyze_traffic(flow: TrafficFlow):
    """
    Receives a flow record, runs L7 signature inspection,
    and returns a threat classification result.
    """
    uri     = flow.uri_path or ""
    body    = flow.body_payload or ""
    headers = flow.http_headers or {}

    # L7 inspection
    l7 = None
    is_malicious = False
    prediction_label = "Normal"

    if uri or body or headers:
        l7 = inspect_http_payload(uri, body, headers)
        if l7["is_l7_malicious"]:
            is_malicious = True
            prediction_label = l7["l7_threat_type"] or "L7_Attack"

    # Network-layer heuristics (no ML models needed)
    pkt = flow.packet_count
    proto = flow.protocol.upper()
    if not is_malicious:
        if proto == "TCP" and pkt >= 500:
            prediction_label = "SYN_Flood"
            is_malicious = True
        elif proto == "UDP" and flow.total_bytes > 500_000:
            prediction_label = "UDP_Flood"
            is_malicious = True
        elif pkt <= 3 and flow.total_bytes < 250:
            prediction_label = "Port_Scan"
            is_malicious = True

    confidence   = 0.97 if is_malicious else 0.95
    anomaly_score = 0.82 if is_malicious else 0.12
    audit_id = f"AUD-{uuid.uuid4().hex[:12].upper()}" if is_malicious else None

    return {
        "status": "success",
        "prediction": prediction_label,
        "prediction_label": prediction_label,
        "confidence": confidence,
        "anomaly_score": anomaly_score,
        "is_malicious": is_malicious,
        "l7_analysis": l7,
        "audit_id": audit_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
