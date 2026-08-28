#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 2: Traffic Gateway
Module: schemas.py
Description: Pydantic schemas for API request validation and response models.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class TrafficConfigSchema(BaseModel):
    """Schema for custom raw packet stream generation."""
    source_ip: str = Field(
        default="192.168.10.10",
        description="Source IPv4 address (explicit or spoofed)",
        examples=["192.168.10.10"],
    )
    destination_ip: str = Field(
        default="192.168.10.20",
        description="Destination IPv4 address",
        examples=["192.168.10.20"],
    )
    protocol: Literal["TCP", "UDP", "ICMP"] = Field(
        default="TCP",
        description="Transport/Network protocol: 'TCP', 'UDP', or 'ICMP'",
        examples=["TCP"],
    )
    source_port: int = Field(
        default=44332,
        ge=1,
        le=65535,
        description="Source transport port (1-65535)",
        examples=[44332],
    )
    destination_port: int = Field(
        default=80,
        ge=1,
        le=65535,
        description="Destination transport port (1-65535)",
        examples=[80],
    )
    packet_count: int = Field(
        default=100,
        ge=1,
        le=100000,
        description="Total number of packets to transmit",
        examples=[100],
    )
    packet_size: Optional[int] = Field(
        default=128,
        ge=28,
        le=9000,
        description="Total target packet size in bytes including headers",
        examples=[128],
    )
    iat: float = Field(
        default=0.01,
        ge=0.0,
        le=10.0,
        description="Inter-arrival time in seconds between consecutive packets",
        examples=[0.01],
    )
    tcp_flags: List[str] = Field(
        default=["ACK"],
        description="List of TCP flag names, e.g. ['SYN'], ['ACK'], ['PSH', 'ACK'], ['FIN']",
        examples=[["ACK"]],
    )
    payload_data: Optional[str] = Field(
        default=None,
        description="Optional application layer payload data",
        examples=["NTRO_CUSTOM_STREAM_DATA"],
    )


class ProfileRequestSchema(BaseModel):
    """Schema for triggering pre-configured baseline and benchmark profiles."""
    profile_name: Literal["normal", "high_velocity_tcp", "port_sweep", "high_volume_udp"] = Field(
        description="Pre-configured traffic profile name",
        examples=["high_velocity_tcp"],
    )
    source_ip: str = Field(
        default="192.168.10.10",
        description="Source IPv4 address",
        examples=["192.168.10.10"],
    )
    destination_ip: str = Field(
        default="192.168.10.20",
        description="Destination IPv4 address",
        examples=["192.168.10.20"],
    )
    packet_count: Optional[int] = Field(
        default=None,
        ge=1,
        le=100000,
        description="Optional packet count override",
        examples=[200],
    )
    iat: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=10.0,
        description="Optional inter-arrival time override in seconds",
        examples=[0.005],
    )


class JobQueuedResponse(BaseModel):
    """Immediate response returned when a background traffic job is queued."""
    job_id: str
    status: str = "queued"
    message: str
    profile: Optional[str] = None


class JobStatusResponse(BaseModel):
    """Response returned when polling job execution status."""
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
