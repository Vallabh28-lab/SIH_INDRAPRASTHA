# NTRO AI-Based Cyber Threat Detection & Forensic Audit System

An enterprise-grade, real-time AI cyber defense platform designed for high-throughput network monitoring (including unidirectional Data Diodes and optical link taps). The system integrates dual-tier machine learning threat classification, SHAP-based Explainable AI (XAI), Geolocation & ASN Threat Intelligence, a SHA-256 cryptographic forensic audit trail (Hyperledger Fabric ready), and a modern React + Vite SOC dashboard.

---

## 1. System Architecture & Topology

```
+---------------------------------------------------------------------------------------------------+
|                                 NTRO REAL-TIME CYBER LAB TOPOLOGY                                 |
|                                 Subnet: 192.168.10.0/24 (Docker Isolated)                         |
+---------------------------------------------------------------------------------------------------+
                                                  |
         +----------------------------------------+----------------------------------------+
         |                                        |                                        |
         v                                        v                                        v
+------------------+                    +------------------+                    +----------------------+
|  source-node-1   |                    |  source-node-2   |                    |   destination-node   |
|  192.168.10.10   |                    |  192.168.10.11   |                    |    192.168.10.20     |
| (Traffic Gen #1) |                    | (Traffic Gen #2) |                    |  (Capture & Flow ML) |
+------------------+                    +------------------+                    +----------------------+
         |                                        |                                        |
         +------------------- Telemetry Injection & Packet Streams ------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                       FASTAPI API GATEWAY                                         |
|                 Telemetry Ingestion (POST /api/traffic) | SOC Polling (GET /api/metrics)          |
+---------------------------------------------------------------------------------------------------+
                                                  |
         +----------------------------------------+----------------------------------------+
         |                                        |                                        |
         v                                        v                                        v
+-----------------------------+       +-----------------------------+       +-----------------------------+
|    AI THREAT DETECTOR       |       |   EXPLAINABLE AI (XAI)      |       |    THREAT INTELLIGENCE      |
|  • Isolation Forest (Anom)  |       |  • SHAP TreeExplainer       |       |  • ASN / Org Lookup         |
|  • XGBoost / Random Forest  | ----> |  • Feature Attribution      | ----> |  • Geo Country / City       |
|  • Multi-Class Threat Label |       |  • Human Justifications     |       |  • IP Reputation Risk Score |
+-----------------------------+       +-----------------------------+       +-----------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        CRYPTOGRAPHIC SHA-256 FORENSIC AUDIT ENGINE                                |
|        • Tamper-Evident Hash Chaining (prev_hash -> audit_hash) | Hyperledger Fabric Ready        |
|        • Audit Persistence: logs/audit_trail.json | Intra-Chain Verification: GET /api/audit/verify|
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                            REACT + VITE + TAILWIND CSS SOC DASHBOARD                              |
|       • Real-Time Metric Counters (Total Flows, Threats Detected, High Risk, Normal Traffic)      |
|       • Recharts Telemetry Volume Trends & Throughput Timeline                                    |
|       • Live Threat Feed with Status Badges (🔴 Malicious vs 🟢 Normal)                          |
|       • Forensic Inspector Drawer Modal (SHAP Breakdown, SHA-256 Hash Copy, Geo/ASN Intel)       |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Complete Phase Breakdown

| Phase | Module | Key Capabilities |
| :--- | :--- | :--- |
| **Phase 1** | `dataset_generator.py` | Statistical synthetic network telemetry profile generation and CICIDS2017 feature mapping. |
| **Phase 2** | `packet_generator.py`, `traffic_profiles.py` | Scapy-backed Layer 3/4 packet injection (Normal, SYN Flood, Port Scan, UDP Flood). |
| **Phase 3** | `packet_capture.py`, `flow_aggregator.py` | Real-time sliding buffer sniffing, bi-directional 5-tuple aggregation, and 13 statistical features. |
| **Phase 4** | `api.py` | FastAPI asynchronous control gateway, job queuing, and JSON telemetry ingestion (`POST /api/traffic`). |
| **Phase 5** | `threat_detector.py`, `ml_engine.py` | Dual-Tier AI Threat Engine: Isolation Forest anomaly score + XGBoost / Random Forest classifier. |
| **Phase 6** | `xai_explainer.py`, `threat_intel.py` | SHAP TreeExplainer attribution & human justifications (`✓ High SYN concentration`) + Geolocation/ASN. |
| **Phase 7** | `audit_logger.py`, `soc-frontend/` | SHA-256 blockchain-style tamper-evident audit logging & React SOC Dashboard. |
| **Phase 8** | `evaluate_system.py` | Automated E2E integration test harness, latency benchmarking, and performance matrix report. |

---

## 3. Technology Stack

- **Backend AI/ML & Core:** Python 3.10+, Scapy, NumPy, Pandas, Scikit-learn, XGBoost, SHAP, Joblib
- **API & Daemon Services:** FastAPI, Uvicorn, Pydantic v2, Requests
- **Forensic & Cryptography:** Python `hashlib` (SHA-256 Block Chaining, Payload Hashing)
- **Frontend SOC Dashboard:** React 18, Vite, Tailwind CSS, Recharts, Lucide-React, Axios
- **Containerization & Network:** Docker, Docker Compose, Linux `tc` traffic control

---

## 4. Empirical Evaluation & Performance Benchmarks

Results generated by executing the automated Phase 8 evaluation harness (`python evaluate_system.py`):

```text
==========================================================================================
 NTRO CYBER THREAT DETECTION SYSTEM - PHASE 8 END-TO-END EVALUATION REPORT
==========================================================================================
 Evaluation Timestamp      : 2026-08-29T15:05:28+00:00
 Total Evaluated Flow Records: 500
------------------------------------------------------------------------------------------
 CORE DETECTION ACCURACY & RELIABILITY METRICS:
   • Overall Accuracy        : 100.00%
   • Weighted Precision      : 100.00%
   • Weighted Recall         : 100.00%
   • Weighted F1-Score       : 100.00%
   • False Positive Rate (FPR): 0.00%
------------------------------------------------------------------------------------------
 CONFUSION MATRIX BREAKDOWN:
   • True Negatives (Normal Correct) : 100
   • False Positives (False Alarms)   : 0
   • False Negatives (Missed Threats) : 0
   • True Positives (Threats Blocked) : 400
------------------------------------------------------------------------------------------
 REAL-TIME PIPELINE LATENCY & THROUGHPUT:
   • Mean Latency / Flow     : 85.097 ms
   • 95th Percentile Latency : 109.860 ms
   • 99th Percentile Latency : 125.823 ms
   • Processing Throughput   : 11.7 flows / sec
------------------------------------------------------------------------------------------
 CRYPTOGRAPHIC FORENSIC AUDIT INTEGRITY:
   • Total Audit Logs Written: 400
   • SHA-256 Chain Integrity : [STATUS: VALID]
   • Corrupted Record Count  : 0
==========================================================================================
```

---

## 5. Installation & Setup Guide

### Prerequisites
- Python 3.10 or higher
- Node.js v18+ and npm
- Docker & Docker Compose (Optional for multinode containerized testbed)

### Step 1: Install Backend Python Dependencies

```powershell
cd CYBER-THREAT-DETECTION\traffic-simulator
pip install -r requirements.txt
```

### Step 2: Install Frontend Dependencies

```powershell
cd CYBER-THREAT-DETECTION\soc-frontend
npm install
```

---

## 6. Running the Platform

### A. Launch Backend API Gateway & AI Services (Terminal 1)
```powershell
cd CYBER-THREAT-DETECTION\traffic-simulator
python api.py
```
- API Swagger Documentation: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`
- Live Metrics: `http://localhost:8000/api/metrics`

### B. Launch React SOC Dashboard (Terminal 2)
```powershell
cd CYBER-THREAT-DETECTION\soc-frontend
npm run dev
```
- Open browser at `http://localhost:5173`

### C. Run Full End-to-End System Evaluation (Terminal 3)
```powershell
cd CYBER-THREAT-DETECTION\traffic-simulator
python evaluate_system.py
```

---

## 7. Live Threat Detection & Explainable AI Output

When a malicious flow is ingested, the engine generates real-time predictions, SHAP justifications, Threat Intel geolocation, and SHA-256 audit proof:

```json
{
  "status": "success",
  "prediction": "SYN_Flood",
  "confidence": 0.9825,
  "anomaly_score": 0.8540,
  "is_malicious": true,
  "xai_explanations": [
    "✓ Extremely high packet rate (846.1 pkts/sec vs normal baseline < 50)",
    "✓ Critical SYN concentration (550 SYN packets with zero ACK responses)",
    "✓ Abnormally low inter-arrival time (mean IAT: 0.0011s indicates automated transmission)"
  ],
  "threat_intel": {
    "source_ip": {
      "ip_address": "10.0.4.88",
      "asn": "AS-LAB-NTRO (Botnet Agent Simulator)",
      "organization": "Adversary Simulation Cluster",
      "country": "India",
      "city": "Bangalore",
      "reputation_score": 95,
      "risk_level": "CRITICAL"
    }
  },
  "audit_id": "AUD-50CF27855C69",
  "audit_hash": "9d013edb59bb42268a6a2ec71eee6c05651b4d8a710087bb73239055bbcdc890"
}
```

---

## 8. Directory Structure

```text
CYBER-THREAT-DETECTION/
├── README.md
├── docker/
│   └── docker-compose.yml
├── traffic-simulator/
│   ├── api.py                    # FastAPI Gateway & SOC endpoints
│   ├── audit_logger.py           # Cryptographic SHA-256 Forensic Audit Manager
│   ├── dataset_generator.py      # Telemetry synthesis engine
│   ├── detection_daemon.py       # Live background sniffer & classification daemon
│   ├── drift_detector.py         # Concept & data drift tracking
│   ├── evaluate_system.py        # Phase 8 E2E benchmark & evaluation harness
│   ├── flow_aggregator.py        # 5-tuple aggregation & feature extraction
│   ├── flow_schema.py            # Pydantic telemetry models
│   ├── ml_engine.py              # ML classification & Isolation Forest model
│   ├── packet_capture.py         # Scapy raw packet sniffing engine
│   ├── packet_generator.py       # Scapy packet crafting & injector
│   ├── requirements.txt          # Python dependency lockfile
│   ├── threat_detector.py        # Dual-tier ML threat classification engine
│   ├── threat_intel.py           # ASN, Geolocation & IP Reputation lookup
│   ├── traffic_profiles.py       # Pre-configured synthetic traffic profiles
│   ├── logs/
│   │   ├── audit_trail.json      # Persistent cryptographic audit logs
│   │   └── evaluation_report.json# Phase 8 benchmark metrics output
│   └── models/                   # Serialized Scaler & Model Joblib artifacts
└── soc-frontend/                 # React + Vite SOC Dashboard Application
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    ├── index.html
    └── src/
        ├── App.jsx               # Main React Application
        ├── main.jsx
        ├── index.css             # Glassmorphism cyber styles
        ├── services/
        │   └── api.js            # Axios API Connector
        └── components/
            ├── Dashboard.jsx     # Main SOC Dashboard with Simulation controls
            ├── MetricsCards.jsx  # Real-time top metrics cards
            ├── TrafficChart.jsx  # Recharts volume trends visualizer
            ├── ThreatsTable.jsx  # Live telemetry & alerts table
            └── ForensicModal.jsx # XAI SHAP drawer & SHA-256 audit inspector
```
