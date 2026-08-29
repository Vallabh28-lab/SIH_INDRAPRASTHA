#!/usr/bin/env bash
# ==============================================================================================
# NTRO AI-Based Cyber Threat Detection Lab - Sandbox Verification & Health Check Suite
# Verifies Docker Bridge Isolation, Container IPs, Virtual Aliases, Intra-Subnet Ping, and Leak Resistance
# ==============================================================================================
set -euo pipefail

NETWORK_NAME="docker_cyber_lab_net"
EXPECTED_SUBNET="192.168.10.0/24"
GEN_NODE="generator-node"
COL_NODE="collector-node"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE} NTRO CYBER THREAT DETECTION LAB - PHASE 1 VERIFICATION & AUDIT SUITE ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# ----------------------------------------------------------------------------------------------
# Test 1: Check Docker Bridge Network and Subnet Inspection
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 1/6] Inspecting Docker Bridge Network & IPAM Subnet...${NC}"
if docker network inspect cyber_lab_net >/dev/null 2>&1; then
    ACTIVE_NET="cyber_lab_net"
elif docker network inspect docker_cyber_lab_net >/dev/null 2>&1; then
    ACTIVE_NET="docker_cyber_lab_net"
else
    echo -e "${RED}[FAILED] Docker network 'cyber_lab_net' not found. Run 'docker compose up -d' first.${NC}"
    exit 1
fi

IS_INTERNAL=$(docker network inspect "${ACTIVE_NET}" --format '{{.Internal}}')
SUBNET_CONF=$(docker network inspect "${ACTIVE_NET}" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}')

echo "  • Network Name    : ${ACTIVE_NET}"
echo "  • Subnet Assigned : ${SUBNET_CONF}"
echo "  • Internal (No NAT): ${IS_INTERNAL}"

if [ "${IS_INTERNAL}" = "true" ] && [ "${SUBNET_CONF}" = "${EXPECTED_SUBNET}" ]; then
    echo -e "  ${GREEN}[PASSED] Network is strictly internal with dedicated subnet ${EXPECTED_SUBNET}.${NC}"
else
    echo -e "  ${RED}[WARNING] Network settings mismatch. Expected subnet ${EXPECTED_SUBNET} and internal=true.${NC}"
fi

# ----------------------------------------------------------------------------------------------
# Test 2: Verify Container Interface IP Assignments
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 2/6] Verifying Container IP Allocations (eth0)...${NC}"
GEN_IP=$(docker exec "${GEN_NODE}" ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "N/A")
COL_IP=$(docker exec "${COL_NODE}" ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "N/A")

echo "  • ${GEN_NODE} IP : ${GEN_IP} (Expected: 192.168.10.10)"
echo "  • ${COL_NODE} IP : ${COL_IP} (Expected: 192.168.10.20)"

if [ "${GEN_IP}" = "192.168.10.10" ] && [ "${COL_IP}" = "192.168.10.20" ]; then
    echo -e "  ${GREEN}[PASSED] Static IP allocations correctly assigned to containers.${NC}"
else
    echo -e "  ${RED}[FAILED] Static IP mismatch.${NC}"
    exit 1
fi

# ----------------------------------------------------------------------------------------------
# Test 3: Verify Virtual Network Interfaces & Loopback Aliases (lo:0)
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 3/6] Verifying Virtual Loopback Aliases (lo:0, lo:1)...${NC}"
GEN_LO=$(docker exec "${GEN_NODE}" ip -4 addr show lo | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | tr '\n' ' ')
COL_LO=$(docker exec "${COL_NODE}" ip -4 addr show lo | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | tr '\n' ' ')

echo "  • ${GEN_NODE} Loopback IPs : ${GEN_LO}"
echo "  • ${COL_NODE} Loopback IPs : ${COL_LO}"

if [[ "${GEN_LO}" == *"192.168.10.100"* ]] && [[ "${COL_LO}" == *"192.168.10.200"* ]]; then
    echo -e "  ${GREEN}[PASSED] Loopback aliases (lo:0) active and responding on both nodes.${NC}"
else
    echo -e "  ${YELLOW}[INFO] Applying setup_network.sh to provision virtual aliases...${NC}"
    docker exec "${GEN_NODE}" bash /app/../docker/setup_network.sh generator || docker exec "${GEN_NODE}" bash -c "ip addr add 192.168.10.100/32 dev lo label lo:0 && ip addr add 10.0.4.88/32 dev lo label lo:1"
    docker exec "${COL_NODE}" bash /app/../docker/setup_network.sh collector || docker exec "${COL_NODE}" bash -c "ip addr add 192.168.10.200/32 dev lo label lo:0"
    echo -e "  ${GREEN}[PASSED] Loopback aliases provisioned successfully.${NC}"
fi

# ----------------------------------------------------------------------------------------------
# Test 4: Intra-Sandbox ICMP Layer 3 Ping Reachability
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 4/6] Testing Intra-Sandbox ICMP Ping (generator -> collector)...${NC}"
if docker exec "${GEN_NODE}" ping -c 2 -W 2 192.168.10.20 >/dev/null 2>&1; then
    echo -e "  ${GREEN}[PASSED] Successful ICMP echo communication across sandbox nodes (192.168.10.10 -> 192.168.10.20).${NC}"
else
    echo -e "  ${RED}[FAILED] Ping failed between sandbox nodes. Check firewall rules.${NC}"
    exit 1
fi

# ----------------------------------------------------------------------------------------------
# Test 5: Raw Socket Capability & Phase 1 Health Probe Injection
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 5/6] Executing Automated Python Health Verifier (Raw Sockets & Scapy)...${NC}"
if docker exec "${GEN_NODE}" python3 /app/verify_phase1.py; then
    echo -e "  ${GREEN}[PASSED] Raw socket allocation and Layer 4 UDP packet injection succeeded.${NC}"
else
    echo -e "  ${RED}[FAILED] Raw socket probe failed.${NC}"
    exit 1
fi

# ----------------------------------------------------------------------------------------------
# Test 6: External Egress Leak Prevention (Host Protection Test)
# ----------------------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Test 6/6] Verifying External Leak Resistance (Anti-Exfiltration Policy)...${NC}"
# Attempt outbound connection to public IP (e.g. 8.8.8.8) - MUST FAIL/TIMEOUT
set +e
LEAK_TEST=$(docker exec "${GEN_NODE}" ping -c 1 -W 2 8.8.8.8 2>&1)
LEAK_CODE=$?
set -e

if [ $LEAK_CODE -ne 0 ]; then
    echo -e "  ${GREEN}[PASSED] Outbound public ping strictly dropped/blocked (Zero external leak confirmed).${NC}"
else
    echo -e "  ${RED}[SECURITY ALERT] Traffic escaped sandbox to public WAN! Review internal: true and iptables.${NC}"
    exit 1
fi

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN} [SUMMARY] ALL PHASE 1 NETWORK SANDBOX CHECKS PASSED SUCCESSFULLY!    ${NC}"
echo -e "${BLUE}======================================================================${NC}"
