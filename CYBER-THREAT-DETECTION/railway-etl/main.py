import os
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from etl_pipeline import extract, transform, load

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
