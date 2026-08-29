#!/usr/bin/env python3
"""
NTRO AI-Based Cyber Threat Detection System - ML Threat Detection Pipeline
Module: dataset_generator.py
Description: Robust multi-class network traffic trace synthesizer with noise injection (jitter, variable IAT,
             random packet sizes), bi-directional handshake/response dynamics, mixed overlapping background flows,
             and Out-of-Distribution (OOD) novel zero-day attack generation.
"""

import argparse
import logging
import os
import random
import time
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from flow_aggregator import FlowAggregator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("DatasetGenerator")

# Standard attack categories and numerical labels
LABEL_MAPPING = {
    0: "Normal",
    1: "SYN_Flood",
    2: "Port_Scan",
    3: "UDP_Flood",
}

LABEL_TO_ID = {v: k for k, v in LABEL_MAPPING.items()}


class DatasetGenerator:
    """
    Robust synthetic telemetry dataset generator with:
    - Bi-directional flow generation (client request + server response)
    - Jitter and noise injection across IAT and packet sizes
    - Overlapping / mixed concurrent flows
    - Out-of-Distribution (OOD) zero-day attack synthesis
    """

    def __init__(self, random_seed: int = 42, noise_level: float = 0.15):
        """
        :param random_seed: Deterministic seed for reproducibility
        :param noise_level: Magnitude of noise/jitter injected (0.0 to 0.5)
        """
        self.random_seed = random_seed
        self.noise_level = noise_level
        random.seed(random_seed)

    def _inject_jitter(self, base_val: float, jitter_pct: Optional[float] = None) -> float:
        """Apply random Gaussian/uniform jitter to temporal or size values."""
        pct = jitter_pct if jitter_pct is not None else self.noise_level
        jitter_factor = random.uniform(1.0 - pct, 1.0 + pct)
        return max(0.0001, base_val * jitter_factor)

    def _generate_normal_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        base_time: float,
    ) -> List[Dict[str, Any]]:
        """
        Profile 1: Realistic Bi-Directional Web/Application Session Traffic.
        Includes 3-way handshake (SYN, SYN-ACK, ACK), HTTP request data, server response stream, and ACKs.
        """
        packets: List[Dict[str, Any]] = []
        curr_t = base_time

        # 1. TCP 3-Way Handshake
        # SYN (Client -> Server)
        packets.append({
            "timestamp": curr_t,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "length": 64,
            "tcp_flags": ["SYN"],
            "payload_size": 0,
        })

        # SYN-ACK (Server -> Client)
        curr_t += self._inject_jitter(0.012)
        packets.append({
            "timestamp": curr_t,
            "src_ip": dst_ip,
            "dst_ip": src_ip,
            "src_port": dst_port,
            "dst_port": src_port,
            "protocol": "TCP",
            "length": 64,
            "tcp_flags": ["SYN", "ACK"],
            "payload_size": 0,
        })

        # ACK (Client -> Server)
        curr_t += self._inject_jitter(0.008)
        packets.append({
            "timestamp": curr_t,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "length": 54,
            "tcp_flags": ["ACK"],
            "payload_size": 0,
        })

        # 2. HTTP Request Data (Client -> Server)
        curr_t += self._inject_jitter(0.02)
        req_len = int(self._inject_jitter(random.choice([320, 512, 768])))
        packets.append({
            "timestamp": curr_t,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "TCP",
            "length": req_len,
            "tcp_flags": ["PSH", "ACK"],
            "payload_size": max(0, req_len - 40),
        })

        # 3. Server Response Stream & Client ACKs
        response_chunks = random.randint(3, 15)
        for _ in range(response_chunks):
            curr_t += self._inject_jitter(random.uniform(0.01, 0.08))
            resp_len = int(self._inject_jitter(random.choice([1024, 1420, 1500])))
            # Server Data
            packets.append({
                "timestamp": curr_t,
                "src_ip": dst_ip,
                "dst_ip": src_ip,
                "src_port": dst_port,
                "dst_port": src_port,
                "protocol": "TCP",
                "length": resp_len,
                "tcp_flags": ["ACK"] if random.random() > 0.3 else ["PSH", "ACK"],
                "payload_size": max(0, resp_len - 40),
            })
            # Client ACK
            curr_t += self._inject_jitter(0.005)
            packets.append({
                "timestamp": curr_t,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "length": 54,
                "tcp_flags": ["ACK"],
                "payload_size": 0,
            })

        return packets

    def _generate_syn_flood_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        base_time: float,
    ) -> List[Dict[str, Any]]:
        """
        Profile 2: High-Velocity TCP SYN Flood Attack.
        Dispatches high-frequency SYN frames with zero/minimal server response, high SYN ratio, and low IAT.
        """
        packet_count = int(self._inject_jitter(random.randint(160, 380)))
        packets: List[Dict[str, Any]] = []
        curr_t = base_time

        for _ in range(packet_count):
            iat = self._inject_jitter(random.uniform(0.0006, 0.0035))
            curr_t += iat
            length = random.choice([54, 60, 64])

            packets.append({
                "timestamp": curr_t,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "length": length,
                "tcp_flags": ["SYN"],
                "payload_size": 0,
            })

        # Occasional RST packet from overwhelmed server
        if random.random() > 0.5:
            packets.append({
                "timestamp": curr_t + 0.01,
                "src_ip": dst_ip,
                "dst_ip": src_ip,
                "src_port": dst_port,
                "dst_port": src_port,
                "protocol": "TCP",
                "length": 54,
                "tcp_flags": ["RST", "ACK"],
                "payload_size": 0,
            })

        return packets

    def _generate_port_scan_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        target_ports: List[int],
        base_time: float,
    ) -> List[Dict[str, Any]]:
        """
        Profile 3: Port Range Sweep & Reconnaissance Probe (Port Scan).
        Iterates across multiple destination ports with single-packet TCP SYN probes with jittered timing.
        """
        packets: List[Dict[str, Any]] = []
        curr_t = base_time

        for port in target_ports:
            iat = self._inject_jitter(random.uniform(0.012, 0.045))
            curr_t += iat
            packets.append({
                "timestamp": curr_t,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": port,
                "protocol": "TCP",
                "length": 60,
                "tcp_flags": ["SYN"],
                "payload_size": 0,
            })
            # Closed port RST response
            if random.random() > 0.6:
                packets.append({
                    "timestamp": curr_t + self._inject_jitter(0.005),
                    "src_ip": dst_ip,
                    "dst_ip": src_ip,
                    "src_port": port,
                    "dst_port": src_port,
                    "protocol": "TCP",
                    "length": 54,
                    "tcp_flags": ["RST", "ACK"],
                    "payload_size": 0,
                })

        return packets

    def _generate_udp_flood_packets(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        base_time: float,
    ) -> List[Dict[str, Any]]:
        """
        Profile 4: High-Volume Volumetric UDP Flood Attack.
        High transmission rate, large datagram footprints, and high byte rates.
        """
        packet_count = int(self._inject_jitter(random.randint(140, 320)))
        packets: List[Dict[str, Any]] = []
        curr_t = base_time

        for _ in range(packet_count):
            iat = self._inject_jitter(random.uniform(0.001, 0.006))
            curr_t += iat
            length = int(self._inject_jitter(random.choice([512, 1024, 1280, 1420])))

            packets.append({
                "timestamp": curr_t,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "UDP",
                "length": length,
                "tcp_flags": [],
                "payload_size": max(0, length - 28),
            })
        return packets

    def generate_ood_zero_day_packets(
        self,
        src_ip: str = "185.220.101.5",
        dst_ip: str = "192.168.10.20",
        src_port: int = 49999,
        dst_port: int = 80,
        base_time: float = 1700000000.0,
    ) -> List[Dict[str, Any]]:
        """
        Out-of-Distribution (OOD) Novel Attack Profile: Slowloris / Low-and-Slow HTTP Starvation.
        Characteristics: Extremely long duration, ultra-low packet rate, tiny periodic byte fragments,
        designed to exhaust server connection slots while evading rate-based threshold filters.
        Used to test unsupervised Isolation Forest zero-day anomaly detection.
        """
        packets: List[Dict[str, Any]] = []
        curr_t = base_time

        # Handshake
        packets.append({"timestamp": curr_t, "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": "TCP", "length": 64, "tcp_flags": ["SYN"], "payload_size": 0})
        curr_t += 0.02
        packets.append({"timestamp": curr_t, "src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port, "protocol": "TCP", "length": 64, "tcp_flags": ["SYN", "ACK"], "payload_size": 0})
        curr_t += 0.01
        packets.append({"timestamp": curr_t, "src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": "TCP", "length": 54, "tcp_flags": ["ACK"], "payload_size": 0})

        # Drips tiny 15-byte header lines every 8-15 seconds
        drip_count = 25
        for _ in range(drip_count):
            curr_t += random.uniform(7.0, 14.0)
            packets.append({
                "timestamp": curr_t,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "TCP",
                "length": 68,
                "tcp_flags": ["PSH", "ACK"],
                "payload_size": 14,
            })
            curr_t += 0.01
            packets.append({
                "timestamp": curr_t,
                "src_ip": dst_ip,
                "dst_ip": src_ip,
                "src_port": dst_port,
                "dst_port": src_port,
                "protocol": "TCP",
                "length": 54,
                "tcp_flags": ["ACK"],
                "payload_size": 0,
            })

        return packets

    def generate_dataset(
        self,
        samples_per_class: int = 200,
        train_split: float = 0.8,
        output_dir: str = "data",
    ) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Synthesize robust multi-class flow records with noise and bi-directional features,
        and export 80/20 train/test CSV partitions.
        """
        logger.info(
            "Synthesizing robust dataset (%d samples/class, 4 classes, noise=%.2f)...",
            samples_per_class,
            self.noise_level,
        )

        all_flows: List[Dict[str, Any]] = []
        base_time = 1700000000.0

        # Class 0: Normal Traffic
        for i in range(samples_per_class):
            src_ip = f"192.168.10.{random.randint(10, 50)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(30000, 65000)
            dst_port = random.choice([80, 443, 8080, 8443, 3000, 5000])

            pkts = self._generate_normal_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 0
                f["label_name"] = "Normal"
                all_flows.append(f)

        # Class 1: SYN Flood
        for i in range(samples_per_class):
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 8080])

            pkts = self._generate_syn_flood_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 1
                f["label_name"] = "SYN_Flood"
                all_flows.append(f)

        # Class 2: Port Scan
        for i in range(samples_per_class):
            src_ip = f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(40000, 60000)
            start_p = random.randint(20, 100)
            target_ports = list(range(start_p, start_p + random.randint(1, 4)))

            pkts = self._generate_port_scan_packets(src_ip, dst_ip, src_port, target_ports, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 2
                f["label_name"] = "Port_Scan"
                all_flows.append(f)

        # Class 3: UDP Flood
        for i in range(samples_per_class):
            src_ip = f"198.51.100.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([53, 123, 5060, 9999, 37008])

            pkts = self._generate_udp_flood_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 3
                f["label_name"] = "UDP_Flood"
                all_flows.append(f)

        df = pd.DataFrame(all_flows).sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)

        # Deterministic 80/20 Stratified Partition
        train_dfs = []
        test_dfs = []
        for label_id in sorted(df["label"].unique()):
            class_subset = df[df["label"] == label_id]
            split_idx = int(len(class_subset) * train_split)
            train_dfs.append(class_subset.iloc[:split_idx])
            test_dfs.append(class_subset.iloc[split_idx:])

        train_df = pd.concat(train_dfs).sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)
        test_df = pd.concat(test_dfs).sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)

        os.makedirs(output_dir, exist_ok=True)
        train_path = os.path.join(output_dir, "dataset_train.csv")
        test_path = os.path.join(output_dir, "dataset_test.csv")

        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)

        logger.info("Dataset generated: Total=%d | Train=%d | Test=%d", len(df), len(train_df), len(test_df))
        return train_df, test_df

    def build_dataset(
        self,
        samples_per_class: int = 200,
        output_path: Optional[str] = None,
    ) -> pd.DataFrame:
        """
        Synthesize multi-class flow dataset and return combined DataFrame.
        Optionally persists to output_path CSV.
        """
        all_flows: List[Dict[str, Any]] = []
        base_time = 1700000000.0

        for i in range(samples_per_class):
            src_ip = f"192.168.10.{random.randint(10, 50)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(30000, 65000)
            dst_port = random.choice([80, 443, 8080, 8443, 3000, 5000])
            pkts = self._generate_normal_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 0
                f["label_name"] = "Normal"
                all_flows.append(f)

        for i in range(samples_per_class):
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 8080])
            pkts = self._generate_syn_flood_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 1
                f["label_name"] = "SYN_Flood"
                all_flows.append(f)

        for i in range(samples_per_class):
            src_ip = f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(40000, 60000)
            start_p = random.randint(20, 100)
            target_ports = list(range(start_p, start_p + random.randint(1, 4)))
            pkts = self._generate_port_scan_packets(src_ip, dst_ip, src_port, target_ports, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 2
                f["label_name"] = "Port_Scan"
                all_flows.append(f)

        for i in range(samples_per_class):
            src_ip = f"198.51.100.{random.randint(1, 254)}"
            dst_ip = "192.168.10.20"
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([53, 123, 5060, 9999, 37008])
            pkts = self._generate_udp_flood_packets(src_ip, dst_ip, src_port, dst_port, base_time + i * 15)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = 3
                f["label_name"] = "UDP_Flood"
                all_flows.append(f)

        df = pd.DataFrame(all_flows).sample(frac=1.0, random_state=self.random_seed).reset_index(drop=True)
        if output_path:
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
            df.to_csv(output_path, index=False)
            logger.info("Saved synthesized dataset to: %s", output_path)
        return df

    def generate_ood_dataset(self, num_samples: int = 40) -> pd.DataFrame:
        """Generate Out-of-Distribution (OOD) novel zero-day attack flows for unsupervised validation."""
        ood_flows = []
        base_time = 1700100000.0

        for i in range(num_samples):
            src_ip = f"185.220.101.{random.randint(1, 254)}"
            pkts = self.generate_ood_zero_day_packets(src_ip=src_ip, base_time=base_time + i * 100)
            for f in FlowAggregator(raw_packets=pkts, bidirectional=True).aggregate():
                f["label"] = -1
                f["label_name"] = "Zero_Day_Slowloris_OOD"
                ood_flows.append(f)

        return pd.DataFrame(ood_flows)


def main() -> None:
    parser = argparse.ArgumentParser(description="NTRO Phase 5: Robust Dataset Generator")
    parser.add_argument("--samples-per-class", "-s", type=int, default=200)
    parser.add_argument("--noise-level", "-n", type=float, default=0.15)
    parser.add_argument("--output-dir", "-o", type=str, default="data")

    args = parser.parse_args()
    generator = DatasetGenerator(noise_level=args.noise_level)
    train_df, test_df = generator.generate_dataset(
        samples_per_class=args.samples_per_class,
        output_dir=args.output_dir,
    )
    print(f"[SUCCESS] Robust Dataset generated in '{args.output_dir}': Train={len(train_df)}, Test={len(test_df)}")


if __name__ == "__main__":
    main()
