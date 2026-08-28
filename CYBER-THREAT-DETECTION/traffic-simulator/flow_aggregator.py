#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - Phase 3 & ML Pipeline
Module: flow_aggregator.py
Description: Advanced bi-directional 5-tuple flow aggregation and temporal feature engineering engine.
             Computes forward/backward dynamics, TCP flag asymmetries, and normalized ratio-based features.
"""

from collections import defaultdict
import logging
import statistics
from typing import Any, Dict, List, Optional, Tuple

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None  # type: ignore
    PANDAS_AVAILABLE = False

logger = logging.getLogger("FlowAggregator")


class FlowAggregator:
    """
    Bi-directional 5-tuple flow aggregation and temporal feature engineering engine.
    Extracts statistical distributions, forward/backward asymmetries, and normalized ratio metrics.
    """

    def __init__(self, raw_packets: Optional[List[Dict[str, Any]]] = None, bidirectional: bool = True):
        """
        Initialize the flow aggregator.

        :param raw_packets: List of raw packet dictionaries
        :param bidirectional: If True, aggregates forward and backward packet directions into a single bi-directional flow
        """
        self.raw_packets: List[Dict[str, Any]] = raw_packets or []
        self.bidirectional = bidirectional
        self._aggregated_flows: List[Dict[str, Any]] = []

    def set_packets(self, packets: List[Dict[str, Any]]) -> "FlowAggregator":
        """
        Update the internal packet list and invalidate previously computed flows.

        :param packets: New list of raw packet records
        :return: self
        """
        self.raw_packets = packets
        self._aggregated_flows = []
        return self

    def _get_canonical_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Create a canonical bi-directional flow key and indicate whether the packet is in the forward direction.

        :return: ((canonical_src_ip, canonical_dst_ip, canonical_src_port, canonical_dst_port, protocol), is_forward)
        """
        if not self.bidirectional:
            return (src_ip, dst_ip, src_port, dst_port, protocol), True

        # Determine canonical orientation (lexicographical sorting of IP:Port endpoints)
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            return (src_ip, dst_ip, src_port, dst_port, protocol), True
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol), False

    def _compute_iat_metrics(self, timestamps: List[float]) -> Tuple[float, float]:
        """Compute mean and sample standard deviation of inter-arrival times (IAT)."""
        if len(timestamps) < 2:
            return 0.0, 0.0

        sorted_ts = sorted(timestamps)
        iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

        iat_mean = sum(iats) / len(iats)
        iat_std = statistics.stdev(iats) if len(iats) >= 2 else 0.0

        return round(iat_mean, 6), round(iat_std, 6)

    def _compute_packet_size_metrics(self, lengths: List[int]) -> Tuple[float, float]:
        """Compute mean and sample standard deviation of packet lengths in bytes."""
        if not lengths:
            return 0.0, 0.0

        mean_size = sum(lengths) / len(lengths)
        std_size = statistics.stdev(lengths) if len(lengths) >= 2 else 0.0

        return round(mean_size, 2), round(std_size, 2)

    def aggregate(self) -> List[Dict[str, Any]]:
        """
        Group raw packet sequences into bi-directional 5-tuple network flows and compute
        temporal, asymmetric, and ratio-based statistical features.

        :return: List of aggregated flow feature dictionaries
        """
        if not self.raw_packets:
            self._aggregated_flows = []
            return self._aggregated_flows

        flow_groups: Dict[Tuple[str, str, int, int, str], List[Tuple[Dict[str, Any], bool]]] = defaultdict(list)

        for pkt in self.raw_packets:
            src_ip = str(pkt.get("src_ip", "0.0.0.0"))
            dst_ip = str(pkt.get("dst_ip", "0.0.0.0"))
            src_port = int(pkt.get("src_port", 0))
            dst_port = int(pkt.get("dst_port", 0))
            protocol = str(pkt.get("protocol", "OTHER")).upper()

            canon_key, is_fwd = self._get_canonical_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            flow_groups[canon_key].append((pkt, is_fwd))

        computed_flows: List[Dict[str, Any]] = []

        for (src_ip, dst_ip, src_port, dst_port, protocol), items in flow_groups.items():
            packet_count = len(items)
            pkts = [it[0] for it in items]
            fwd_pkts = [it[0] for it in items if it[1]]
            bwd_pkts = [it[0] for it in items if not it[1]]

            fwd_packet_count = len(fwd_pkts)
            bwd_packet_count = len(bwd_pkts)

            lengths = [int(p.get("length", 0)) for p in pkts]
            fwd_lengths = [int(p.get("length", 0)) for p in fwd_pkts]
            bwd_lengths = [int(p.get("length", 0)) for p in bwd_pkts]

            total_bytes = sum(lengths)
            fwd_bytes = sum(fwd_lengths)
            bwd_bytes = sum(bwd_lengths)

            timestamps = [float(p.get("timestamp", 0.0)) for p in pkts]
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            raw_duration = max_ts - min_ts
            flow_duration = max(raw_duration, 0.0)

            # Throughput calculations (safeguard division by zero for sub-millisecond/instant flows)
            effective_duration = max(flow_duration, 0.0001)
            packets_per_sec = packet_count / effective_duration
            bytes_per_sec = total_bytes / effective_duration
            bwd_packets_per_sec = bwd_packet_count / effective_duration
            byte_rate = total_bytes / effective_duration

            # Statistical packet size distributions
            mean_pkt_size, std_pkt_size = self._compute_packet_size_metrics(lengths)

            # Inter-arrival time distributions
            iat_mean, iat_std = self._compute_iat_metrics(timestamps)

            # TCP flag counts & asymmetries
            syn_count = 0
            syn_ack_count = 0
            ack_count = 0
            fin_count = 0
            rst_count = 0

            for p, is_fwd in items:
                flags = p.get("tcp_flags", [])
                if isinstance(flags, str):
                    flags = [flags]

                has_syn = any("SYN" in f or "S" in f for f in flags)
                has_ack = any("ACK" in f or "A" in f for f in flags)
                has_fin = any("FIN" in f or "F" in f for f in flags)
                has_rst = any("RST" in f or "R" in f for f in flags)

                if has_syn and has_ack:
                    syn_ack_count += 1
                elif has_syn:
                    syn_count += 1

                if has_ack:
                    ack_count += 1
                if has_fin:
                    fin_count += 1
                if has_rst:
                    rst_count += 1

            # Ratio-based normalized features
            syn_ratio = syn_count / max(packet_count, 1)
            ack_ratio = ack_count / max(packet_count, 1)
            syn_ack_ratio = syn_count / max(syn_ack_count + 1, 1)
            fwd_bwd_ratio = fwd_packet_count / max(bwd_packet_count + 1, 1)

            flow_record = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": packet_count,
                "fwd_packet_count": fwd_packet_count,
                "bwd_packet_count": bwd_packet_count,
                "total_bytes": total_bytes,
                "fwd_bytes": fwd_bytes,
                "bwd_bytes": bwd_bytes,
                "flow_duration": round(flow_duration, 6),
                "packets_per_sec": round(packets_per_sec, 2),
                "bytes_per_sec": round(bytes_per_sec, 2),
                "bwd_packets_per_sec": round(bwd_packets_per_sec, 2),
                "mean_packet_size": mean_pkt_size,
                "std_packet_size": std_pkt_size,
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "syn_count": syn_count,
                "syn_ack_count": syn_ack_count,
                "ack_count": ack_count,
                "fin_count": fin_count,
                "rst_count": rst_count,
                "syn_ratio": round(syn_ratio, 4),
                "ack_ratio": round(ack_ratio, 4),
                "syn_ack_ratio": round(syn_ack_ratio, 4),
                "fwd_bwd_ratio": round(fwd_bwd_ratio, 4),
                "byte_rate": round(byte_rate, 2),
            }
            computed_flows.append(flow_record)

        self._aggregated_flows = computed_flows
        logger.info(
            "Aggregated %d raw packets into %d bi-directional 5-tuple flow(s).",
            len(self.raw_packets),
            len(self._aggregated_flows),
        )
        return self._aggregated_flows

    def to_dataframe(self) -> Any:
        """Convert aggregated flow feature vectors into a Pandas DataFrame."""
        if not self._aggregated_flows:
            self.aggregate()

        if PANDAS_AVAILABLE and pd is not None:
            return pd.DataFrame(self._aggregated_flows)
        else:
            logger.warning("Pandas is not installed. Returning list of dictionaries instead.")
            return self._aggregated_flows

    def to_dict(self) -> List[Dict[str, Any]]:
        """Return aggregated flow records as a list of structured dictionaries."""
        if not self._aggregated_flows:
            self.aggregate()
        return self._aggregated_flows

    def summary(self) -> Dict[str, Any]:
        """Compute high-level summary statistics across all extracted flows."""
        flows = self.to_dict()
        total_packets = sum(f["packet_count"] for f in flows)
        total_bytes = sum(f["total_bytes"] for f in flows)
        protocols = sorted(list(set(f["protocol"] for f in flows)))

        return {
            "total_raw_packets": len(self.raw_packets),
            "unique_flows_count": len(flows),
            "total_bytes_aggregated": total_bytes,
            "detected_protocols": protocols,
        }
