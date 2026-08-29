#!/usr/bin/env bash
# ==============================================================================================
# NTRO AI-Based Cyber Threat Detection Lab - Network & Firewall Provisioning Script
# Configures Virtual Interfaces (lo:0, lo:1), Custom Routing, and Strict iptables Sandbox Rules
# ==============================================================================================
set -euo pipefail

NODE_ROLE="${1:-generator}" # 'generator' or 'collector'
SANDBOX_SUBNET="192.168.10.0/24"
PRIMARY_IFACE="eth0"

echo "======================================================================"
echo " [*] Initializing Sandbox Network Isolation & Virtual Interfaces..."
echo " [*] Node Role: ${NODE_ROLE} | Subnet: ${SANDBOX_SUBNET}"
echo "======================================================================"

# ----------------------------------------------------------------------------------------------
# 1. Loopback Alias & Virtual Network Interface Configuration
# ----------------------------------------------------------------------------------------------
echo "[1/4] Configuring Virtual Loopback Aliases (lo:0, lo:1)..."

if [ "${NODE_ROLE}" = "generator" ]; then
    # Generator assigns aliases representing virtual spoofed attack/workstation subnets
    ip addr add 192.168.10.100/32 dev lo label lo:0 2>/dev/null || echo "  [i] lo:0 (192.168.10.100) already assigned."
    ip addr add 10.0.4.88/32 dev lo label lo:1 2>/dev/null || echo "  [i] lo:1 (10.0.4.88) already assigned."
    echo "  [✓] Generator loopback aliases active: lo:0 (192.168.10.100/32), lo:1 (10.0.4.88/32)"
elif [ "${NODE_ROLE}" = "collector" ]; then
    # Collector assigns alias for dedicated forensic telemetry sink
    ip addr add 192.168.10.200/32 dev lo label lo:0 2>/dev/null || echo "  [i] lo:0 (192.168.10.200) already assigned."
    echo "  [✓] Collector loopback alias active: lo:0 (192.168.10.200/32)"
fi

# Ensure loopback is UP
ip link set lo up

# ----------------------------------------------------------------------------------------------
# 2. Kernel Routing & Sysctl Enforcements
# ----------------------------------------------------------------------------------------------
echo "[2/4] Applying Kernel Routing & Anti-Leak Sysctls..."

# Disable IP forwarding (container will not act as a router/gateway)
sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true

# Disable Reverse Path Filtering to allow spoofed source IP injection & asymmetric telemetry flows
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf."${PRIMARY_IFACE}".rp_filter=0 >/dev/null 2>&1 || true

# Accept local traffic bound for loopback virtual IPs
sysctl -w net.ipv4.conf.all.accept_local=1 >/dev/null 2>&1 || true

echo "  [✓] Kernel parameters applied (ip_forward=0, rp_filter=0, accept_local=1)."

# ----------------------------------------------------------------------------------------------
# 3. Strict iptables Firewall Isolation Rules (Host Protection & Zero Egress Leak)
# ----------------------------------------------------------------------------------------------
echo "[3/4] Establishing Strict iptables Firewall Isolation Policies..."

# Flush existing rules and chains
iptables -F
iptables -X
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true

# Set Default DROP Policies on FORWARD and OUTPUT for external security
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# --- INPUT CHAIN RULES ---
# 1. Allow all loopback traffic (localhost, lo:0, lo:1)
iptables -A INPUT -i lo -j ACCEPT

# 2. Allow established/related incoming connections within sandbox
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Allow incoming traffic from within the isolated 192.168.10.0/24 sandbox subnet
iptables -A INPUT -i "${PRIMARY_IFACE}" -s "${SANDBOX_SUBNET}" -j ACCEPT

# 4. Allow ICMP echo requests (ping) within sandbox
iptables -A INPUT -p icmp --icmp-type echo-request -s "${SANDBOX_SUBNET}" -j ACCEPT

# --- OUTPUT CHAIN RULES ---
# 1. Allow all outgoing loopback traffic
iptables -A OUTPUT -o lo -j ACCEPT

# 2. Allow established/related outgoing connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 3. Allow outgoing traffic ONLY within the isolated 192.168.10.0/24 subnet
iptables -A OUTPUT -o "${PRIMARY_IFACE}" -d "${SANDBOX_SUBNET}" -j ACCEPT

# 4. Allow Scapy raw packet injection bound for sandbox destination endpoints
iptables -A OUTPUT -p udp -d "${SANDBOX_SUBNET}" -j ACCEPT
iptables -A OUTPUT -p tcp -d "${SANDBOX_SUBNET}" -j ACCEPT
iptables -A OUTPUT -p icmp -d "${SANDBOX_SUBNET}" -j ACCEPT

# 5. STRICT EXTERNAL LEAK BLOCK: Explicitly reject and log any attempt to route to external LAN/WAN
iptables -A OUTPUT -d 0.0.0.0/0 -j REJECT --reject-with icmp-net-prohibited 2>/dev/null || iptables -A OUTPUT -d 0.0.0.0/0 -j DROP

echo "  [✓] iptables policy configured: Intra-sandbox (192.168.10.0/24) permitted; External WAN/LAN strictly blocked."

# ----------------------------------------------------------------------------------------------
# 4. Display Active Configuration State
# ----------------------------------------------------------------------------------------------
echo "[4/4] Verification of Interface and Routing Table:"
echo "--- IP Address Assignment ---"
ip -4 addr show
echo "--- Kernel Routing Table ---"
ip route show
echo "======================================================================"
echo " [SUCCESS] Sandbox Network Isolation & Virtual Aliases Initialized."
echo "======================================================================"
