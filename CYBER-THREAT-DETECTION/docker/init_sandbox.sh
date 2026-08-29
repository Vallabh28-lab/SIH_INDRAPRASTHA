#!/usr/bin/env bash
# ==============================================================================================
# NTRO AI-Based Cyber Threat Detection Lab - One-Click Sandbox Orchestration & Bring-up Script
# ==============================================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "======================================================================"
echo " [NTRO CYBER LAB] Starting Phase 1 Network Sandbox Environment..."
echo "======================================================================"

# 1. Build and Bring Up Docker Containers in Detached Mode
echo "[1/3] Building & Starting Docker Compose Sandbox..."
docker compose up -d --build

# Wait briefly for container networking stack initialization
sleep 2

# 2. Configure Virtual Loopback Aliases and Firewall Policies
echo "[2/3] Initializing Interfaces, Aliases (lo:0), and iptables Policies..."
docker exec -i generator-node bash -c "
    ip addr add 192.168.10.100/32 dev lo label lo:0 2>/dev/null || true
    ip addr add 10.0.4.88/32 dev lo label lo:1 2>/dev/null || true
    ip link set lo up
    iptables -F && iptables -P FORWARD DROP
    iptables -A OUTPUT -o eth0 -d 192.168.10.0/24 -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
"

docker exec -i generator-node-2 bash -c "
    ip addr add 192.168.10.101/32 dev lo label lo:0 2>/dev/null || true
    ip link set lo up
    iptables -F && iptables -P FORWARD DROP
    iptables -A OUTPUT -o eth0 -d 192.168.10.0/24 -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
"

docker exec -i collector-node bash -c "
    ip addr add 192.168.10.200/32 dev lo label lo:0 2>/dev/null || true
    ip link set lo up
    iptables -F && iptables -P FORWARD DROP
    iptables -A INPUT -i eth0 -s 192.168.10.0/24 -j ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
"

# 3. Run Automated Health & Isolation Verification Suite
echo "[3/3] Running Automated Sandbox Verification Suite..."
chmod +x ./verify_sandbox.sh
./verify_sandbox.sh

echo "======================================================================"
echo " [READY] Phase 1 Controlled Telemetry Environment is Active & Verified."
echo "======================================================================"
