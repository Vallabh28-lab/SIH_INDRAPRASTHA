# NTRO AI-Based Cyber Threat Detection System
## Phase 1, 2 & 3: Environment, Traffic Generation, Ingestion & Flow Analytics

An isolated, reproducible network laboratory designed to simulate, inject, capture, and extract statistical ML flow features from unidirectional IP traffic streams (such as Data Diode or unidirectional optical link feeds) for downstream AI-driven cyber threat detection.

---

## 1. System Architecture & Topology

The lab infrastructure establishes an isolated virtual subnet (`192.168.10.0/24`) containing multiple discrete traffic generator nodes and a centralized packet ingestion/inspection node.

```
                  +----------------------------------------------+
                  |  Docker Bridge Network: cyber_lab_net        |
                  |  Subnet: 192.168.10.0/24                     |
                  +----------------------------------------------+
                                         |
         +-------------------------------+-------------------------------+
         |                               |                               |
         v                               v                               v
+------------------+           +------------------+           +----------------------+
|  source-node-1   |           |  source-node-2   |           |   destination-node   |
|  192.168.10.10   |           |  192.168.10.11   |           |    192.168.10.20     |
| (Traffic Gen #1) |           | (Traffic Gen #2) |           | (Capture & Flow ML)  |
+------------------+           +------------------+           +----------------------+
         |                               |                               ^
         |          UDP / RAW IP         |          UDP / RAW IP         |
         +-------------------------------+-------------------------------+
```

### Directory Structure

```
CYBER-THREAT-DETECTION/
├── docker/
│   └── docker-compose.yml       # 3-Node bridge network definition with CAP_NET_ADMIN
├── traffic-simulator/
│   ├── Dockerfile               # Debian Python 3.11 with net-tools, tcpdump, Scapy
│   ├── requirements.txt         # Core dependencies (scapy, fastapi, pandas, numpy, etc.)
│   ├── test_connectivity.py     # L3/L4 packet generator & dynamic BPF sniffer
│   ├── verify_phase1.py         # Automated lab health check and environment validator
│   ├── schemas.py               # Pydantic schemas for API validation and telemetry
│   ├── packet_generator.py      # Core modular Scapy traffic generation & telemetry metering engine
│   ├── traffic_profiles.py      # Standardized normal & stress benchmark traffic profiles
│   ├── test_generator.py        # CLI execution and performance profiling harness
│   ├── api.py                   # Asynchronous FastAPI Control Gateway with BackgroundTasks
│   ├── test_api_phase2.py       # Automated test client for REST API endpoints & polling
│   ├── packet_capture.py        # Continuous packet sniffer & thread-safe sliding buffer engine
│   ├── test_capture.py          # Standalone CLI capture verification and buffer telemetry report
│   ├── flow_aggregator.py       # 5-Tuple flow aggregator & statistical ML feature extractor
│   └── test_phase3.py           # End-to-end packet capture & flow feature extraction runner
└── README.md
```

---

## 2. Quickstart & Deployment Guide

### Prerequisites
- Docker Engine (v20.10+) and Docker Compose (v2.0+)
- Host support for Linux network namespaces

### Step 1: Build and Launch the Lab Environment
From the root of `CYBER-THREAT-DETECTION/`, run:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

Verify that all three nodes are healthy and running:

```bash
docker compose -f docker/docker-compose.yml ps
```

---

## 3. Automated Lab Health Check

Run the automated verification script on `source-node-1` to validate the environment configuration:

```bash
docker exec -it source-node-1 python verify_phase1.py
```

---

## 4. Phase 2: Traffic Profiles & CLI Telemetry Harness

The Phase 2 engine (`packet_generator.py`, `traffic_profiles.py`, `test_generator.py`) provides benchmark traffic generators that meter throughput, duration, packet rate, and byte counts.

### Running Traffic Profiles from `source-node-1`:

```bash
# 1. Normal Web Session Profile (TCP PSH+ACK, ~0.1s IAT)
docker exec -it source-node-1 python test_generator.py --profile normal

# 2. High-Velocity TCP SYN Benchmark (TCP SYN, 0.005s IAT)
docker exec -it source-node-1 python test_generator.py --profile high_velocity_tcp --count 200

# 3. Port Sweep Profile (Sequential ports 20 -> 70)
docker exec -it source-node-1 python test_generator.py --profile port_sweep

# 4. High-Volume UDP Datagram Benchmark (UDP 1024-byte payloads, 0.002s IAT)
docker exec -it source-node-1 python test_generator.py --profile high_volume_udp

# 5. Run All Profiles Sequentially with JSON Output
docker exec -it source-node-1 python test_generator.py --profile all --json
```

---

## 5. Phase 2: Asynchronous FastAPI Control Gateway

The `api.py` service exposes asynchronous REST API routes that trigger packet synthesis as background tasks.

### Starting the API Server
```bash
docker exec -d source-node-1 python -m uvicorn api:app --host 0.0.0.0 --port 8000
```

### Triggering a Profile Asynchronously via cURL

```bash
curl -X POST http://192.168.10.10:8000/api/v1/traffic/profile \
  -H "Content-Type: application/json" \
  -d '{
    "profile_name": "high_velocity_tcp",
    "source_ip": "192.168.10.10",
    "destination_ip": "192.168.10.20",
    "packet_count": 200,
    "iat": 0.005
  }'
```

---

## 6. Phase 3: Packet Capture, 5-Tuple Flow Aggregation & Feature Extraction

Phase 3 provides end-to-end ingestion and statistical feature extraction for ML anomaly detection:
- `packet_capture.py`: Continuous sniffer with sliding buffer.
- `flow_aggregator.py`: Aggregates packets by `(src_ip, dst_ip, src_port, dst_port, protocol)` and calculates features:
  * `packet_count`, `total_bytes`, `flow_duration`, `packets_per_sec`, `bytes_per_sec`
  * `mean_packet_size`, `std_packet_size`, `iat_mean`, `iat_std`, `syn_count`, `ack_count`

### End-to-End Flow Feature Extraction Test

In **Terminal 1**, run `test_phase3.py` on `destination-node` to capture and extract flow feature vectors:

```bash
docker exec -it destination-node python test_phase3.py --target-count 200 --timeout 15
```

In **Terminal 2**, transmit a multi-profile traffic burst from `source-node-1`:

```bash
docker exec -it source-node-1 python test_generator.py --profile high_velocity_tcp --count 200
```

*Sample Extracted Flow Feature Table (DataFrame Output):*
```text
====================================================================================================
 5-TUPLE FLOW AGGREGATION & STATISTICAL FEATURE VECTORS
====================================================================================================
  Total Raw Packets Processed : 200
  Distinct 5-Tuple Flows       : 1
  Total Aggregated Bytes       : 12800
  Detected Protocols           : ['TCP']
====================================================================================================

        src_ip         dst_ip  src_port  dst_port protocol  packet_count  total_bytes  flow_duration  packets_per_sec  bytes_per_sec  mean_packet_size  std_packet_size  iat_mean   iat_std  syn_count  ack_count
 192.168.10.10  192.168.10.20     49152        80      TCP           200        12800         1.0542           189.72       12141.91              64.0              0.0  0.005298  0.000184        200          0
====================================================================================================
```

---

## 7. Security & Configuration Notes

- **`cap_add: - NET_ADMIN`**: Essential for containerized environments to allow raw socket creation (`AF_PACKET`) without running full unconfined privileged containers.
- **Unidirectional Context**: In downstream phases, the destination node's return path (ARP/ICMP replies) can be blocked via `iptables` or simulated unidirectional diodes to mimic air-gapped unidirectional communication taps.

---

## 8. Teardown

To shut down and clean up containers and isolated bridge networks:

```bash
docker compose -f docker/docker-compose.yml down
```
