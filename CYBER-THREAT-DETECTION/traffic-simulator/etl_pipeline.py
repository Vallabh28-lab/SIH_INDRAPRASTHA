#!/usr/bin/env python3
"""
NTRO Cyber Threat Detection - ETL Pipeline with MongoDB Integration
Module: etl_pipeline.py

Three-phase pipeline:
  Extract   - reads raw records from JSON or CSV source files
  Transform - cleans fields, resolves aliases, runs L7 inspection,
              adds derived flags and etl_processed_at timestamp
  Load      - writes enriched records to MongoDB (processed_flows collection)
              and prints a summary report
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import pandas as pd
import pymongo

from l7_inspector import inspect_http_payload

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ETLPipeline")

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME = "security_warehouse"
COLLECTION_NAME = "processed_flows"

# ---------------------------------------------------------------------------
# Column alias map — normalises CSV field names to schema field names
# ---------------------------------------------------------------------------
_ALIASES = {
    "src_ip":            "source_ip",
    "dst_ip":            "destination_ip",
    "src_port":          "source_port",
    "dst_port":          "destination_port",
    "packets_per_sec":   "packets_per_second",
    "bytes_per_sec":     "bytes_per_second",
}

# Numeric columns that must be non-negative; fill NaN with 0
_NUMERIC_COLS = [
    "source_port", "destination_port", "packet_count", "total_bytes",
    "packets_per_second", "bytes_per_second", "iat_mean",
    "syn_count", "ack_count", "flow_duration",
]

# Required string columns; fill NaN with empty string then strip
_STRING_COLS = ["source_ip", "destination_ip", "protocol"]


# =============================================================================
# STEP 1 — EXTRACT
# =============================================================================

def extract(source_path: str) -> pd.DataFrame:
    """
    Read raw records from a JSON array file or a CSV file.
    Returns a raw DataFrame; raises on unrecognised extension.
    Malformed rows are skipped with a warning rather than crashing.
    """
    ext = os.path.splitext(source_path)[1].lower()
    logger.info("[EXTRACT] Reading source: %s", source_path)

    try:
        if ext == ".json":
            with open(source_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            df = pd.DataFrame(records)

        elif ext == ".csv":
            df = pd.read_csv(source_path, on_bad_lines="warn")

        else:
            raise ValueError(f"Unsupported source format: '{ext}'. Use .json or .csv")

    except (json.JSONDecodeError, pd.errors.ParserError) as exc:
        logger.error("[EXTRACT] Failed to parse %s: %s", source_path, exc)
        raise

    logger.info("[EXTRACT] Loaded %d raw records", len(df))
    return df


# =============================================================================
# STEP 2 — TRANSFORM
# =============================================================================

def _resolve_aliases(df: pd.DataFrame) -> pd.DataFrame:
    """Rename aliased column names to canonical schema names."""
    return df.rename(columns={k: v for k, v in _ALIASES.items() if k in df.columns})


def _clean_fields(df: pd.DataFrame) -> pd.DataFrame:
    """
    - Strip whitespace from string columns
    - Normalise protocol to uppercase
    - Fill numeric NaN with 0
    - Drop rows where source_ip or destination_ip is null/empty
    """
    for col in _STRING_COLS:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str).str.strip()

    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].str.upper().where(
            df["protocol"].str.upper().isin(["TCP", "UDP", "ICMP", "OTHER"]),
            other="OTHER",
        )

    for col in _NUMERIC_COLS:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).clip(lower=0)

    before = len(df)
    df = df[df["source_ip"].str.len() > 0].copy()
    dropped = before - len(df)
    if dropped:
        logger.warning("[TRANSFORM] Dropped %d rows with missing source_ip", dropped)

    return df


def _parse_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    """Parse a 'timestamp' column if present; add etl_processed_at."""
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    df["etl_processed_at"] = datetime.now(timezone.utc).isoformat()
    return df


def _run_l7_inspection(row: pd.Series) -> dict[str, Any]:
    """
    Invoke inspect_http_payload when any L7 field is present.
    Returns the l7_analysis dict or None.
    """
    uri    = row.get("uri_path")
    body   = row.get("body_payload")
    headers  = row.get("http_headers")

    has_l7 = (
        (isinstance(uri,    str) and uri.strip()) or
        (isinstance(body,    str) and body.strip()) or
        (isinstance(headers, dict) and headers)
    )

    if not has_l7:
        return None

    return inspect_http_payload(
        uri_path=uri     if isinstance(uri,  str) else "",
        body_payload=body if isinstance(body, str) else "",
        headers=headers  if isinstance(headers, dict) else {},
    )


def transform(df: pd.DataFrame) -> pd.DataFrame:
    """
    Full transform phase:
      1. Resolve column aliases
      2. Clean and standardise fields
      3. Parse timestamps, add etl_processed_at
      4. Run L7 inspection per row
      5. Derive is_l7_malicious and l7_threat_type columns
    """
    logger.info("[TRANSFORM] Starting transform on %d records", len(df))

    df = _resolve_aliases(df)
    df = _clean_fields(df)
    df = _parse_timestamps(df)

    # Run L7 inspection — stored as a dict column, then exploded into flat cols
    df["l7_analysis"]     = df.apply(_run_l7_inspection, axis=1)
    df["is_l7_malicious"] = df["l7_analysis"].apply(
        lambda x: x["is_l7_malicious"] if isinstance(x, dict) else False
    )
    df["l7_threat_type"]  = df["l7_analysis"].apply(
        lambda x: x["l7_threat_type"] if isinstance(x, dict) else None
    )
    df["matched_signatures"] = df["l7_analysis"].apply(
        lambda x: x["matched_signatures"] if isinstance(x, dict) else []
    )

    l7_hits = df["is_l7_malicious"].sum()
    logger.info(
        "[TRANSFORM] Complete. %d/%d records flagged as L7 malicious",
        l7_hits, len(df),
    )
    return df


# =============================================================================
# STEP 3 — LOAD (MONGODB)
# =============================================================================

def load(df: pd.DataFrame) -> None:
    """
    Persist enriched records to MongoDB collection 'processed_flows'.
    Prints a summary report to stdout.
    """
    try:
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command('ping') # Test connection
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]
    except Exception as exc:
        logger.error("[LOAD] Failed to connect to MongoDB at %s: %s", MONGO_URI, exc)
        raise

    # Convert DataFrame records to clean dicts, handling NaNs and timestamps safely.
    # pd.isna() raises ValueError on multi-element objects (dicts, lists, numpy arrays),
    # so we guard with explicit type checks before calling it.
    records = []
    for record in df.to_dict(orient="records"):
        cleaned_record = {}
        for k, v in record.items():
            if v is None:
                cleaned_record[k] = None
            elif isinstance(v, pd.Timestamp):
                cleaned_record[k] = v.isoformat()
            elif isinstance(v, float) and pd.isna(v):
                cleaned_record[k] = None
            else:
                cleaned_record[k] = v
        records.append(cleaned_record)

    if records:
        # Insert records into MongoDB
        result = collection.insert_many(records)
        logger.info("[LOAD] Successfully loaded %d documents into MongoDB (%s.%s)", 
                    len(result.inserted_ids), DB_NAME, COLLECTION_NAME)
    else:
        logger.warning("[LOAD] No records to load into MongoDB.")

    _print_summary(df, f"MongoDB -> {DB_NAME}.{COLLECTION_NAME}")


def _print_summary(df: pd.DataFrame, target_info: str) -> None:
    SEP = "=" * 68
    print(f"\n{SEP}")
    print("  NTRO ETL PIPELINE - PROCESSING SUMMARY")
    print(SEP)
    print(f"  Total records processed : {len(df)}")
    print(f"  L7 malicious detected   : {int(df['is_l7_malicious'].sum())}")

    threat_counts = df[df["is_l7_malicious"]]["l7_threat_type"].value_counts()
    if not threat_counts.empty:
        print("  L7 threat breakdown     :")
        for threat, count in threat_counts.items():
            print(f"    {threat:<22} {count}")

    if "label_name" in df.columns:
        label_counts = df["label_name"].value_counts()
        print("  Ground-truth labels     :")
        for label, count in label_counts.items():
            print(f"    {label:<22} {count}")

    print(f"  Target Destination      : {target_info}")
    print(SEP + "\n")


# =============================================================================
# PIPELINE RUNNER
# =============================================================================

def run_pipeline(source_path: str) -> pd.DataFrame:
    """Execute the full Extract -> Transform -> Load pipeline."""
    logger.info("ETL pipeline started for source: %s", source_path)
    raw_df       = extract(source_path)
    enriched_df  = transform(raw_df)
    load(enriched_df)
    logger.info("ETL pipeline complete.")
    return enriched_df


if __name__ == "__main__":
    import sys

    # Default: run against the JSON sample; pass a CSV path as argv[1] to override
    source = sys.argv[1] if len(sys.argv) > 1 else os.path.join(BASE_DIR, "data", "traffic_logs.json")
    run_pipeline(source)