#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Gateway
Module: api.py
Description: Asynchronous FastAPI Control Gateway for remote and programmatic traffic generation.
"""

from datetime import datetime
import logging
import sys
from typing import Any, Dict, List, Optional
import uuid
from fastapi import BackgroundTasks, FastAPI, HTTPException, status
import uvicorn

from packet_generator import PacketGenerator
from schemas import (
    JobQueuedResponse,
    JobStatusResponse,
    ProfileRequestSchema,
    TrafficConfigSchema,
)
from traffic_profiles import (
    generate_high_velocity_tcp,
    generate_high_volume_udp,
    generate_normal_traffic,
    generate_port_sweep,
)

# Configure logger
logger = logging.getLogger("TrafficGatewayAPI")

app = FastAPI(
    title="NTRO Traffic Simulator Control Gateway",
    description="REST API Gateway to trigger background L3/L4 packet streams and benchmark profiles for Cyber Threat Detection.",
    version="2.0.0",
)

# In-memory thread-safe job repository
jobs_db: Dict[str, Dict[str, Any]] = {}


def _execute_custom_traffic_job(job_id: str, config: TrafficConfigSchema) -> None:
    """Worker function executed in the background for custom traffic configurations."""
    jobs_db[job_id]["status"] = "running"
    jobs_db[job_id]["started_at"] = datetime.utcnow().isoformat()
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
        jobs_db[job_id]["completed_at"] = datetime.utcnow().isoformat()
        jobs_db[job_id]["metrics"] = metrics
        logger.info("Background traffic job [%s] COMPLETED successfully.", job_id)

    except Exception as exc:
        logger.error("Background traffic job [%s] FAILED: %s", job_id, exc)
        jobs_db[job_id]["status"] = "failed"
        jobs_db[job_id]["completed_at"] = datetime.utcnow().isoformat()
        jobs_db[job_id]["error"] = str(exc)


def _execute_profile_traffic_job(job_id: str, request: ProfileRequestSchema) -> None:
    """Worker function executed in the background for pre-configured traffic profiles."""
    jobs_db[job_id]["status"] = "running"
    jobs_db[job_id]["started_at"] = datetime.utcnow().isoformat()
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
            # port_sweep does not use packet_count directly (calculated from start_port/end_port)
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
        jobs_db[job_id]["completed_at"] = datetime.utcnow().isoformat()
        jobs_db[job_id]["metrics"] = metrics
        logger.info("Background profile job [%s] COMPLETED successfully.", job_id)

    except Exception as exc:
        logger.error("Background profile job [%s] FAILED: %s", job_id, exc)
        jobs_db[job_id]["status"] = "failed"
        jobs_db[job_id]["completed_at"] = datetime.utcnow().isoformat()
        jobs_db[job_id]["error"] = str(exc)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["System"])
def health_check():
    """Health check endpoint confirming API gateway readiness."""
    return {
        "status": "healthy",
        "service": "traffic-simulator-gateway",
        "version": "2.0.0",
        "active_jobs_count": len(jobs_db),
    }


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
        "created_at": datetime.utcnow().isoformat(),
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
        "created_at": datetime.utcnow().isoformat(),
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


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
