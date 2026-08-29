#!/usr/bin/env python3
"""
====================================================================================================
NTRO AI-Based Cyber Threat Detection System - Phase 3: Packet Capture & Flow Aggregation
Module: flow_aggregator.py
Role: Senior Systems and Network Telemetry Engineer

Description:
    Real-time stateful packet capture and 5-tuple bi-directional network flow aggregation engine.
    Transforms high-velocity raw packet streams into structured temporal telemetry records,
    computing forward/backward traffic dynamics, statistical packet size distributions,
    high-precision inter-arrival time (IAT) metrics (mean, min, max, std), and TCP flag distributions.

Capabilities:
    1. Canonical Bi-Directional 5-Tuple Keying:
       Identifies flows by (Src/Dst IP, Src/Dst Port, Protocol) with lexicographical ordering.
    2. Statistical Feature Extraction:
       - Flow duration, throughput (Packets/Sec, Bytes/Sec).
       - Packet size metrics (Min, Max, Mean, Standard Deviation).
       - Temporal IAT metrics (Min, Max, Mean, Standard Deviation).
       - Directional asymmetries (Forward vs Backward Packet/Byte Ratios).
       - TCP flag counts (SYN, ACK, FIN, RST, PSH, URG, SYN-ACK) and normalized ratios.
    3. Real-Time Sliding Window Sniffing:
       Continuous interface listening via Scapy AsyncSniffer with configurable time windows.
    4. Multi-Format Serialization:
       Exports to REST API schema dictionaries, Pandas DataFrames, or raw JSON.
====================================================================================================
"""

import argparse
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
import json
import logging
import math
import os
import signal
import statistics
import sys
import threading
import time
from typing import Any, Callable, Deque, Dict, Iterator, List, Optional, Tuple, Union

# Structured Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("FlowAggregator")

# Pandas Import with Graceful Fallback
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    pd = None  # type: ignore
    PANDAS_AVAILABLE = False

# Scapy Import for Live Packet Capture Capabilities
try:
    from scapy.all import (
        ICMP,
        IP,
        TCP,
        UDP,
        AsyncSniffer,
        Raw,
        conf,
        get_if_list,
        sniff,
    )
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning(
        "Scapy is not installed. Live network interface sniffing is disabled; batch aggregation mode active."
    )


# ==================================================================================================
# 1. Telemetry Data Schemas & Records
# ==================================================================================================

@dataclass
class FlowRecord:
    """Structured bi-directional 5-tuple network flow telemetry record."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    fwd_packet_count: int
    bwd_packet_count: int
    total_bytes: int
    fwd_bytes: int
    bwd_bytes: int
    flow_duration: float
    packets_per_sec: float
    bytes_per_sec: float
    bwd_packets_per_sec: float
    min_packet_size: int
    max_packet_size: int
    mean_packet_size: float
    std_packet_size: float
    iat_mean: float
    iat_min: float
    iat_max: float
    iat_std: float
    syn_count: int
    syn_ack_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    psh_count: int
    urg_count: int
    syn_ratio: float
    ack_ratio: float
    syn_ack_ratio: float
    fwd_bwd_ratio: float
    byte_rate: float

    def to_dict(self) -> Dict[str, Any]:
        """Serialize flow record to standardized dictionary."""
        return asdict(self)

    def to_api_schema(self) -> Dict[str, Any]:
        """
        Serialize flow record to REST API schema format (FlowRecordSchema compatible).
        Maps src_ip -> source_ip, dst_ip -> destination_ip, etc.
        """
        data = asdict(self)
        data["source_ip"] = self.src_ip
        data["destination_ip"] = self.dst_ip
        data["source_port"] = self.src_port
        data["destination_port"] = self.dst_port
        data["packets_per_second"] = self.packets_per_sec
        data["bytes_per_second"] = self.bytes_per_sec
        return data


# ==================================================================================================
# 2. Main Flow Aggregator Class
# ==================================================================================================

class FlowAggregator:
    """
    Bi-directional 5-tuple flow aggregation and temporal feature engineering engine.
    Extracts statistical distributions, forward/backward asymmetries, and normalized ratio metrics.
    """

    TCP_FLAG_MAP = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }

    def __init__(
        self,
        raw_packets: Optional[List[Dict[str, Any]]] = None,
        bidirectional: bool = True,
    ):
        """
        Initialize the flow aggregator.

        :param raw_packets: Optional list of raw packet dictionaries.
        :param bidirectional: If True, aggregates forward & backward directions into a canonical 5-tuple.
        """
        self.raw_packets: List[Dict[str, Any]] = raw_packets or []
        self.bidirectional = bidirectional
        self._aggregated_flows: List[Dict[str, Any]] = []

    def set_packets(self, packets: List[Dict[str, Any]]) -> "FlowAggregator":
        """
        Update the internal packet list and invalidate previously computed flows.

        :param packets: New list of raw packet records.
        :return: self
        """
        self.raw_packets = packets
        self._aggregated_flows = []
        return self

    def add_packet(self, packet: Dict[str, Any]) -> None:
        """Append a single raw packet dictionary to the aggregator."""
        self.raw_packets.append(packet)
        self._aggregated_flows = []

    # ----------------------------------------------------------------------------------------------
    # Canonical 5-Tuple Keying & Orientation
    # ----------------------------------------------------------------------------------------------
    def _get_canonical_flow_key(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> Tuple[Tuple[str, str, int, int, str], bool]:
        """
        Create a canonical bi-directional flow key and determine whether the packet is in the forward direction.

        :return: ((canonical_src_ip, canonical_dst_ip, canonical_src_port, canonical_dst_port, protocol), is_forward)
        """
        if not self.bidirectional:
            return (src_ip, dst_ip, src_port, dst_port, protocol), True

        # Lexicographical canonical sorting based on (IP, Port) endpoints
        endpoint_a = (src_ip, src_port)
        endpoint_b = (dst_ip, dst_port)

        if endpoint_a <= endpoint_b:
            return (src_ip, dst_ip, src_port, dst_port, protocol), True
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol), False

    # ----------------------------------------------------------------------------------------------
    # Statistical Feature Calculations
    # ----------------------------------------------------------------------------------------------
    def _compute_iat_metrics(self, timestamps: List[float]) -> Tuple[float, float, float, float]:
        """
        Compute mean, min, max, and sample standard deviation of inter-arrival times (IAT).

        :return: (iat_mean, iat_min, iat_max, iat_std)
        """
        if len(timestamps) < 2:
            return 0.0, 0.0, 0.0, 0.0

        sorted_ts = sorted(timestamps)
        iats = [sorted_ts[i] - sorted_ts[i - 1] for i in range(1, len(sorted_ts))]

        if not iats:
            return 0.0, 0.0, 0.0, 0.0

        iat_mean = sum(iats) / len(iats)
        iat_min = min(iats)
        iat_max = max(iats)
        iat_std = statistics.stdev(iats) if len(iats) >= 2 else 0.0

        return (
            round(iat_mean, 6),
            round(iat_min, 6),
            round(iat_max, 6),
            round(iat_std, 6),
        )

    def _compute_packet_size_metrics(self, lengths: List[int]) -> Tuple[int, int, float, float]:
        """
        Compute min, max, mean, and sample standard deviation of packet lengths in bytes.

        :return: (min_size, max_size, mean_size, std_size)
        """
        if not lengths:
            return 0, 0, 0.0, 0.0

        min_size = min(lengths)
        max_size = max(lengths)
        mean_size = sum(lengths) / len(lengths)
        std_size = statistics.stdev(lengths) if len(lengths) >= 2 else 0.0

        return min_size, max_size, round(mean_size, 2), round(std_size, 2)

    # ----------------------------------------------------------------------------------------------
    # Core Aggregation Logic
    # ----------------------------------------------------------------------------------------------
    def aggregate(self) -> List[Dict[str, Any]]:
        """
        Group raw packet sequences into bi-directional 5-tuple network flows and compute
        temporal, asymmetric, and ratio-based statistical features.

        :return: List of aggregated flow feature dictionaries.
        """
        if not self.raw_packets:
            self._aggregated_flows = []
            return self._aggregated_flows

        flow_groups: Dict[
            Tuple[str, str, int, int, str], List[Tuple[Dict[str, Any], bool]]
        ] = defaultdict(list)

        for pkt in self.raw_packets:
            src_ip = str(pkt.get("src_ip", "0.0.0.0"))
            dst_ip = str(pkt.get("dst_ip", "0.0.0.0"))
            src_port = int(pkt.get("src_port", 0))
            dst_port = int(pkt.get("dst_port", 0))
            protocol = str(pkt.get("protocol", "OTHER")).upper()

            canon_key, is_fwd = self._get_canonical_flow_key(
                src_ip, dst_ip, src_port, dst_port, protocol
            )
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
            min_ts = min(timestamps) if timestamps else 0.0
            max_ts = max(timestamps) if timestamps else 0.0
            raw_duration = max_ts - min_ts
            flow_duration = max(raw_duration, 0.0)

            # Throughput calculations (safeguard division by zero for sub-millisecond/instant flows)
            effective_duration = max(flow_duration, 0.0001)
            packets_per_sec = packet_count / effective_duration
            bytes_per_sec = total_bytes / effective_duration
            bwd_packets_per_sec = bwd_packet_count / effective_duration
            byte_rate = total_bytes / effective_duration

            # Statistical packet size distributions
            min_size, max_size, mean_pkt_size, std_pkt_size = self._compute_packet_size_metrics(lengths)

            # Inter-arrival time distributions
            iat_mean, iat_min, iat_max, iat_std = self._compute_iat_metrics(timestamps)

            # TCP flag counts & asymmetries
            syn_count = 0
            syn_ack_count = 0
            ack_count = 0
            fin_count = 0
            rst_count = 0
            psh_count = 0
            urg_count = 0

            for p, _ in items:
                flags = p.get("tcp_flags", [])
                if isinstance(flags, str):
                    flags = [flags]

                # Exact token matching to prevent false substring matches (e.g. 'S' inside 'PSH')
                flag_set = {f.strip().upper() for f in flags}

                has_syn = bool(flag_set & {"SYN", "S"})
                has_ack = bool(flag_set & {"ACK", "A"})
                has_fin = bool(flag_set & {"FIN", "F"})
                has_rst = bool(flag_set & {"RST", "R"})
                has_psh = bool(flag_set & {"PSH", "P"})
                has_urg = bool(flag_set & {"URG", "U"})

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
                if has_psh:
                    psh_count += 1
                if has_urg:
                    urg_count += 1


            # Ratio-based normalized features
            syn_ratio = syn_count / max(packet_count, 1)
            ack_ratio = ack_count / max(packet_count, 1)
            syn_ack_ratio = syn_count / max(syn_ack_count + 1, 1)
            fwd_bwd_ratio = fwd_packet_count / max(bwd_packet_count + 1, 1)

            record = FlowRecord(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_count=packet_count,
                fwd_packet_count=fwd_packet_count,
                bwd_packet_count=bwd_packet_count,
                total_bytes=total_bytes,
                fwd_bytes=fwd_bytes,
                bwd_bytes=bwd_bytes,
                flow_duration=round(flow_duration, 6),
                packets_per_sec=round(packets_per_sec, 2),
                bytes_per_sec=round(bytes_per_sec, 2),
                bwd_packets_per_sec=round(bwd_packets_per_sec, 2),
                min_packet_size=min_size,
                max_packet_size=max_size,
                mean_packet_size=mean_pkt_size,
                std_packet_size=std_pkt_size,
                iat_mean=iat_mean,
                iat_min=iat_min,
                iat_max=iat_max,
                iat_std=iat_std,
                syn_count=syn_count,
                syn_ack_count=syn_ack_count,
                ack_count=ack_count,
                fin_count=fin_count,
                rst_count=rst_count,
                psh_count=psh_count,
                urg_count=urg_count,
                syn_ratio=round(syn_ratio, 4),
                ack_ratio=round(ack_ratio, 4),
                syn_ack_ratio=round(syn_ack_ratio, 4),
                fwd_bwd_ratio=round(fwd_bwd_ratio, 4),
                byte_rate=round(byte_rate, 2),
            )
            computed_flows.append(record.to_dict())

        self._aggregated_flows = computed_flows
        logger.debug(
            "Aggregated %d raw packets into %d bi-directional 5-tuple flow(s).",
            len(self.raw_packets),
            len(self._aggregated_flows),
        )
        return self._aggregated_flows

    # ----------------------------------------------------------------------------------------------
    # Output Serializers & Data Representation
    # ----------------------------------------------------------------------------------------------
    def to_dict(self) -> List[Dict[str, Any]]:
        """Return aggregated flow records as a list of structured dictionaries."""
        if not self._aggregated_flows:
            self.aggregate()
        return self._aggregated_flows

    def to_api_records(self) -> List[Dict[str, Any]]:
        """Return aggregated flow records matching REST API ingestion schema (FlowRecordSchema)."""
        flows = self.to_dict()
        api_records: List[Dict[str, Any]] = []
        for f in flows:
            rec = dict(f)
            rec["source_ip"] = f["src_ip"]
            rec["destination_ip"] = f["dst_ip"]
            rec["source_port"] = f["src_port"]
            rec["destination_port"] = f["dst_port"]
            rec["packets_per_second"] = f["packets_per_sec"]
            rec["bytes_per_second"] = f["bytes_per_sec"]
            api_records.append(rec)
        return api_records

    def to_dataframe(self) -> Any:
        """Convert aggregated flow feature vectors into a Pandas DataFrame."""
        if not self._aggregated_flows:
            self.aggregate()

        if PANDAS_AVAILABLE and pd is not None:
            return pd.DataFrame(self._aggregated_flows)
        else:
            logger.warning("Pandas is not installed. Returning list of dictionaries.")
            return self._aggregated_flows

    def summary(self) -> Dict[str, Any]:
        """Compute high-level session summary statistics across all extracted flows."""
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


# ==================================================================================================
# 3. Real-Time Sliding-Window Sniffing & Aggregation Engine
# ==================================================================================================

class RealTimeFlowSniffer:
    """
    Continuous real-time packet capturing and sliding-window flow aggregation daemon.
    Listens on a designated interface and periodically emits aggregated 5-tuple flow records.
    """

    def __init__(
        self,
        interface: str = "eth0",
        window_seconds: float = 3.0,
        bpf_filter: Optional[str] = None,
        callback: Optional[Callable[[List[Dict[str, Any]]], None]] = None,
    ):
        self.interface = interface
        self.window_seconds = max(0.5, window_seconds)
        self.bpf_filter = bpf_filter
        self.callback = callback

        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=20000)
        self._lock = threading.Lock()
        self._is_running = False
        self._sniffer: Optional[AsyncSniffer] = None
        self._worker_thread: Optional[threading.Thread] = None

    def _packet_handler(self, pkt) -> None:
        """Internal callback for Scapy AsyncSniffer."""
        if IP not in pkt:
            return

        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)

        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        tcp_flags = []
        payload_size = 0

        if TCP in pkt:
            protocol = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            flags_str = str(pkt[TCP].flags)
            tcp_flags = [FlowAggregator.TCP_FLAG_MAP[c] for c in flags_str if c in FlowAggregator.TCP_FLAG_MAP]
        elif UDP in pkt:
            protocol = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif ICMP in pkt:
            protocol = "ICMP"

        if Raw in pkt:
            payload_size = len(pkt[Raw].load)

        record = {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": pkt_len,
            "tcp_flags": tcp_flags,
            "payload_size": payload_size,
        }

        with self._lock:
            self._buffer.append(record)

    def _window_processor(self) -> None:
        """Background thread executing periodic sliding-window flow aggregation."""
        logger.info(
            "Sliding-window processor active (Window Interval: %.2fs)", self.window_seconds
        )
        while self._is_running:
            time.sleep(self.window_seconds)

            with self._lock:
                if not self._buffer:
                    continue
                # Drain current buffer
                snapshot = list(self._buffer)
                self._buffer.clear()

            if snapshot:
                aggregator = FlowAggregator(raw_packets=snapshot, bidirectional=True)
                flow_records = aggregator.aggregate()

                logger.info(
                    "[FlowSniffer Window] Processed %d frames -> %d distinct 5-tuple flow(s)",
                    len(snapshot),
                    len(flow_records),
                )

                if self.callback and flow_records:
                    try:
                        self.callback(flow_records)
                    except Exception as cb_err:
                        logger.error("Error invoking window callback: %s", cb_err)

    def start(self) -> None:
        """Start real-time sniffing and sliding window processing."""
        if self._is_running:
            logger.warning("RealTimeFlowSniffer is already running.")
            return

        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for real-time interface sniffing.")

        self._is_running = True
        logger.info(
            "Starting RealTimeFlowSniffer on interface '%s' (Filter: %s, Window: %.2fs)...",
            self.interface,
            self.bpf_filter or "None",
            self.window_seconds,
        )

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False,
            )
            self._sniffer.start()

            self._worker_thread = threading.Thread(target=self._window_processor, daemon=True)
            self._worker_thread.start()
            logger.info("RealTimeFlowSniffer successfully initialized.")
        except Exception as exc:
            self._is_running = False
            logger.critical("Failed to start RealTimeFlowSniffer: %s", exc)
            raise

    def stop(self) -> None:
        """Stop packet sniffing and terminate background worker."""
        if not self._is_running:
            return

        logger.info("Stopping RealTimeFlowSniffer...")
        self._is_running = False

        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as e:
                logger.warning("Error stopping AsyncSniffer: %s", e)

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=2.0)

        logger.info("RealTimeFlowSniffer terminated cleanly.")


# ==================================================================================================
# 4. Command-Line Interface (CLI) Entrypoint
# ==================================================================================================

def format_flows_table(flows: List[Dict[str, Any]]) -> str:
    """Format extracted flow feature records into an aligned terminal table."""
    if not flows:
        return "No flows captured."

    headers = [
        "5-Tuple (Endpoint -> Endpoint)",
        "Proto",
        "Pkts (Fwd/Bwd)",
        "Bytes",
        "Duration",
        "PPS",
        "Mean Size",
        "IAT Mean",
        "SYN/ACK",
    ]
    rows = []
    for f in flows:
        endpoint_str = f"{f['src_ip']}:{f['src_port']} -> {f['dst_ip']}:{f['dst_port']}"
        pkts_str = f"{f['packet_count']} ({f['fwd_packet_count']}/{f['bwd_packet_count']})"
        syn_ack_str = f"{f['syn_count']}/{f['ack_count']}"

        rows.append([
            endpoint_str,
            f["protocol"],
            pkts_str,
            f"{f['total_bytes']:,}",
            f"{f['flow_duration']:.4f}s",
            f"{f['packets_per_sec']:,.1f}",
            f"{f['mean_packet_size']:.1f}B",
            f"{f['iat_mean']:.5f}s",
            syn_ack_str,
        ])

    col_widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]
    
    separator = "+" + "+".join(["-" * (w + 2) for w in col_widths]) + "+"
    header_line = "| " + " | ".join(f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers))) + " |"
    
    table_lines = [separator, header_line, separator]
    for row in rows:
        row_line = "| " + " | ".join(f"{str(row[i]):<{col_widths[i]}}" for i in range(len(row))) + " |"
        table_lines.append(row_line)
    table_lines.append(separator)

    return "\n".join(table_lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="NTRO AI Threat Detection Lab - Phase 3: Packet Capture & Flow Aggregation Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  1. Live Interface Capture & 3-Second Sliding Window Flow Extraction:
     python flow_aggregator.py --interface eth0 --window 3.0

  2. Continuous Live Sniffing with JSON Stream Output:
     python flow_aggregator.py --interface eth0 --window 2.0 --json
        """,
    )

    parser.add_argument(
        "--interface",
        "-i",
        type=str,
        default="eth0",
        help="Network interface to sniff (default: eth0)",
    )
    parser.add_argument(
        "--window",
        "-w",
        type=float,
        default=3.0,
        help="Sliding aggregation window in seconds (default: 3.0)",
    )
    parser.add_argument(
        "--filter",
        "-f",
        type=str,
        default=None,
        help="Optional BPF filter (e.g. 'tcp or udp')",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output extracted flow records as JSON instead of formatted table",
    )

    args = parser.parse_args()

    print("=" * 80)
    print(" NTRO CYBER THREAT DETECTION - PHASE 3 FLOW AGGREGATION ENGINE")
    print("=" * 80)
    print(f"[*] Interface       : {args.interface}")
    print(f"[*] Window Duration : {args.window} seconds")
    print(f"[*] BPF Filter      : {args.filter or 'None (All IPv4 Traffic)'}")
    print("=" * 80)

    def print_window_flows(flows: List[Dict[str, Any]]) -> None:
        if args.json:
            print(json.dumps(flows, indent=2))
        else:
            print(f"\n[Window Timestamp: {time.strftime('%H:%M:%S')}] Extracted {len(flows)} Active Flow(s):")
            print(format_flows_table(flows))

    sniffer = RealTimeFlowSniffer(
        interface=args.interface,
        window_seconds=args.window,
        bpf_filter=args.filter,
        callback=print_window_flows,
    )

    try:
        sniffer.start()
        print("[*] Sniffer running. Press Ctrl+C to terminate...")
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
    finally:
        sniffer.stop()
        print("[*] Flow aggregation terminated cleanly.")


if __name__ == "__main__":
    main()
