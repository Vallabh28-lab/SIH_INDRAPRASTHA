#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 4: Telemetry Schema
Module: flow_schema.py
Description: Pydantic schema validation for standardized network flow telemetry records.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class FlowRecordSchema(BaseModel):
    """
    Standardized Network Flow Telemetry Schema for REST ingestion and AI inference.
    """
    source_ip: str = Field(
        ...,
        description="Source IPv4 address of the flow",
        examples=["192.168.10.10"],
    )
    destination_ip: str = Field(
        ...,
        description="Destination IPv4 address of the flow",
        examples=["10.0.20.10"],
    )
    protocol: str = Field(
        ...,
        description="L4 Protocol (TCP, UDP, ICMP)",
        examples=["TCP"],
    )
    packet_count: int = Field(
        ...,
        ge=1,
        description="Total number of packets in flow",
        examples=[1000],
    )
    total_bytes: int = Field(
        ...,
        ge=0,
        description="Total byte count of all packets",
        examples=[1200000],
    )
    packets_per_second: float = Field(
        ...,
        ge=0.0,
        description="Throughput in packets per second",
        examples=[500.0],
    )
    bytes_per_second: float = Field(
        ...,
        ge=0.0,
        description="Throughput in bytes per second",
        examples=[600000.0],
    )
    iat_mean: float = Field(
        ...,
        ge=0.0,
        description="Mean inter-arrival time between packets in seconds",
        examples=[0.002],
    )
    syn_count: int = Field(
        ...,
        ge=0,
        description="Total packets with SYN flag",
        examples=[1000],
    )
    ack_count: int = Field(
        ...,
        ge=0,
        description="Total packets with ACK flag",
        examples=[0],
    )

    # Optional extended 5-tuple fields
    source_port: Optional[int] = Field(
        default=0,
        ge=0,
        le=65535,
        description="Source transport port (optional)",
    )
    destination_port: Optional[int] = Field(
        default=0,
        ge=0,
        le=65535,
        description="Destination transport port (optional)",
    )
    flow_duration: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Flow duration in seconds (optional)",
    )
    iat_std: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Standard deviation of inter-arrival times (optional)",
    )

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, v: str) -> str:
        return v.strip().upper()

    model_config = {
        "json_schema_extra": {
            "example": {
                "source_ip": "192.168.10.10",
                "destination_ip": "10.0.20.10",
                "protocol": "TCP",
                "packet_count": 1000,
                "total_bytes": 1200000,
                "packets_per_second": 500.0,
                "bytes_per_second": 600000.0,
                "iat_mean": 0.002,
                "syn_count": 1000,
                "ack_count": 0,
            }
        }
    }
