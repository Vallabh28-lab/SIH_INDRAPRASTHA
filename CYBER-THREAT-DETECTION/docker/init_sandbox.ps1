# ==============================================================================================
# NTRO AI-Based Cyber Threat Detection Lab - PowerShell Sandbox Bring-up Script
# ==============================================================================================
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " [NTRO CYBER LAB] Starting Phase 1 Network Sandbox Environment (PowerShell)..." -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $scriptPath

# 1. Build and Bring Up Docker Compose
Write-Host "`n[1/3] Building & Starting Docker Compose Sandbox..." -ForegroundColor Yellow
docker compose up -d --build

Start-Sleep -Seconds 2

# 2. Configure Virtual Aliases & Isolation Rules
Write-Host "`n[2/3] Initializing Interfaces, Aliases (lo:0, lo:1), and iptables Policies..." -ForegroundColor Yellow
docker exec generator-node bash -c "ip addr add 192.168.10.100/32 dev lo label lo:0 2>/dev/null || true; ip addr add 10.0.4.88/32 dev lo label lo:1 2>/dev/null || true; ip link set lo up; iptables -F; iptables -P FORWARD DROP; iptables -A OUTPUT -o eth0 -d 192.168.10.0/24 -j ACCEPT; iptables -A OUTPUT -o lo -j ACCEPT"
docker exec generator-node-2 bash -c "ip addr add 192.168.10.101/32 dev lo label lo:0 2>/dev/null || true; ip link set lo up; iptables -F; iptables -P FORWARD DROP; iptables -A OUTPUT -o eth0 -d 192.168.10.0/24 -j ACCEPT; iptables -A OUTPUT -o lo -j ACCEPT"
docker exec collector-node bash -c "ip addr add 192.168.10.200/32 dev lo label lo:0 2>/dev/null || true; ip link set lo up; iptables -F; iptables -P FORWARD DROP; iptables -A INPUT -i eth0 -s 192.168.10.0/24 -j ACCEPT; iptables -A INPUT -i lo -j ACCEPT"

# 3. Verification
Write-Host "`n[3/3] Executing Sandbox Verification..." -ForegroundColor Yellow
& "$scriptPath\verify_sandbox.ps1"

