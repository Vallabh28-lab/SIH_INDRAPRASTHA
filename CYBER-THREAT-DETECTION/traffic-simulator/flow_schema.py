#!/usr/bin/env python3
"""
====================================================================================================
NTRO AI-Based Cyber Threat Detection System - Phase 4: Telemetry Data Validation Schema
Module: flow_schema.py
Role: Backend Systems & API Architect

Description:
    Strict, production-grade Pydantic v2 data models for validating bi-directional 5-tuple
    network flow records ingested via the FastAPI gateway (POST /api/traffic).
    Enforces protocol normalization, IP validation, numerical boundaries, and standardizes
    CICIDS2017 / NetFlow statistical feature attributes.
====================================================================================================
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class FlowRecordSchema(BaseModel):
    """
    Standardized Network Flow Telemetry Schema for REST ingestion and AI inference.
    Matches all 5-tuple statistical features engineered by FlowAggregator.
    """

    # --- Core 5-Tuple Identifiers ---
    source_ip: str = Field(
        ...,
        description="Source IPv4 address of the flow",
        examples=["192.168.10.10"],
    )
    destination_ip: str = Field(
        ...,
        description="Destination IPv4 address of the flow",
        examples=["192.168.10.20"],
    )
    source_port: int = Field(
        default=0,
        ge=0,
        le=65535,
        description="Source transport port (0-65535)",
        examples=[54321],
    )
    destination_port: int = Field(
        default=0,
        ge=0,
        le=65535,
        description="Destination target port (0-65535)",
        examples=[80],
    )
    protocol: str = Field(
        ...,
        description="Transport/Network Layer Protocol (TCP, UDP, ICMP, OTHER)",
        examples=["TCP"],
    )

    # --- Volumetric & Throughput Features ---
    packet_count: int = Field(
        ...,
        ge=1,
        description="Total packet count in flow",
        examples=[100],
    )
    fwd_packet_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Packets in forward direction (Client -> Server)",
        examples=[60],
    )
    bwd_packet_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Packets in backward direction (Server -> Client)",
        examples=[40],
    )
    total_bytes: int = Field(
        ...,
        ge=0,
        description="Total byte count of all packets",
        examples=[38400],
    )
    fwd_bytes: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total forward byte count",
        examples=[23040],
    )
    bwd_bytes: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total backward byte count",
        examples=[15360],
    )
    flow_duration: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Total flow duration in seconds",
        examples=[2.951],
    )
    packets_per_second: float = Field(
        ...,
        ge=0.0,
        description="Packet throughput rate in packets per second",
        examples=[33.88],
    )
    bytes_per_second: float = Field(
        ...,
        ge=0.0,
        description="Bandwidth throughput in bytes per second",
        examples=[13012.5],
    )
    byte_rate: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Byte rate in bytes per second",
        examples=[13012.5],
    )

    # --- Packet Size Distribution ---
    mean_packet_size: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Mean packet length in bytes",
        examples=[384.0],
    )
    std_packet_size: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Standard deviation of packet lengths",
        examples=[12.5],
    )
    min_packet_size: Optional[int] = Field(
        default=0,
        ge=0,
        description="Minimum packet length in bytes",
        examples=[64],
    )
    max_packet_size: Optional[int] = Field(
        default=0,
        ge=0,
        description="Maximum packet length in bytes",
        examples=[1400],
    )

    # --- Inter-Arrival Time (IAT) Metrics ---
    iat_mean: float = Field(
        ...,
        ge=0.0,
        description="Mean inter-arrival time in seconds",
        examples=[0.0298],
    )
    iat_std: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Standard deviation of inter-arrival times",
        examples=[0.005],
    )
    iat_min: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Minimum inter-arrival time in seconds",
        examples=[0.001],
    )
    iat_max: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Maximum inter-arrival time in seconds",
        examples=[0.052],
    )

    # --- TCP Flag Counts & Ratio Metrics ---
    syn_count: int = Field(
        ...,
        ge=0,
        description="Total packets with SYN flag",
        examples=[1],
    )
    syn_ack_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total packets with SYN-ACK flags",
        examples=[1],
    )
    ack_count: int = Field(
        ...,
        ge=0,
        description="Total packets with ACK flag",
        examples=[99],
    )
    fin_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total packets with FIN flag",
        examples=[0],
    )
    rst_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total packets with RST flag",
        examples=[0],
    )
    psh_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total packets with PSH flag",
        examples=[30],
    )
    urg_count: Optional[int] = Field(
        default=0,
        ge=0,
        description="Total packets with URG flag",
        examples=[0],
    )
    syn_ratio: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Ratio of SYN packets to total packets",
        examples=[0.01],
    )
    ack_ratio: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Ratio of ACK packets to total packets",
        examples=[0.99],
    )
    syn_ack_ratio: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Ratio of SYN to SYN-ACK responses",
        examples=[0.5],
    )
    fwd_bwd_ratio: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        description="Ratio of forward to backward packet counts",
        examples=[1.5],
    )

    # ----------------------------------------------------------------------------------------------
    # Field Validators & Normalizers
    # ----------------------------------------------------------------------------------------------
    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ipv4_address(cls, v: str) -> str:
        """Validate that IP address is a syntactically valid IPv4 string."""
        v_clean = v.strip()
        try:
            ipaddress.IPv4Address(v_clean)
            return v_clean
        except ValueError:
            raise ValueError(f"Invalid IPv4 address format: '{v}'")

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, v: str) -> str:
        """Normalize protocol to uppercase standard token."""
        cleaned = v.strip().upper()
        if cleaned not in ("TCP", "UDP", "ICMP", "OTHER"):
            return "OTHER"
        return cleaned

    @model_validator(mode="before")
    @classmethod
    def reconcile_aliased_fields(cls, values: Any) -> Any:
        """Reconcile alternative naming conventions (e.g. src_ip -> source_ip, packets_per_sec -> packets_per_second)."""
        if isinstance(values, dict):
            if "src_ip" in values and "source_ip" not in values:
                values["source_ip"] = values["src_ip"]
            if "dst_ip" in values and "destination_ip" not in values:
                values["destination_ip"] = values["dst_ip"]
            if "src_port" in values and "source_port" not in values:
                values["source_port"] = values["src_port"]
            if "dst_port" in values and "destination_port" not in values:
                values["destination_port"] = values["dst_port"]
            if "packets_per_sec" in values and "packets_per_second" not in values:
                values["packets_per_second"] = values["packets_per_sec"]
            if "bytes_per_sec" in values and "bytes_per_second" not in values:
                values["bytes_per_second"] = values["bytes_per_sec"]
        return values

    model_config = {
        "json_schema_extra": {
            "example": {
                "source_ip": "192.168.10.10",
                "destination_ip": "192.168.10.20",
                "source_port": 54321,
                "destination_port": 80,
                "protocol": "TCP",
                "packet_count": 100,
                "total_bytes": 38400,
                "packets_per_second": 33.88,
                "bytes_per_second": 13012.5,
                "iat_mean": 0.0298,
                "syn_count": 1,
                "ack_count": 99,
                "flow_duration": 2.951,
                "syn_ratio": 0.01,
                "ack_ratio": 0.99,
            }
        }
    }


class IngestionResponseSchema(BaseModel):
    """Standardized response schema returned on successful telemetry ingestion."""
    status: str = "success"
    message: str = "Flow record validated, ingested, and persisted successfully"
    prediction: str = "Normal"
    confidence: float = 0.98
    anomaly_score: float = 0.05
    is_malicious: bool = False
    audit_hash: Optional[str] = None
    audit_id: Optional[str] = None
    timestamp: str
    persisted_to_filestore: bool = True
    received_flow: Dict[str, Any]
