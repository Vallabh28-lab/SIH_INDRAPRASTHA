# ==============================================================================================
# NTRO AI-Based Cyber Threat Detection Lab - PowerShell Sandbox Verification Script
# ==============================================================================================
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " NTRO CYBER THREAT DETECTION LAB - PHASE 1 VERIFICATION (PowerShell)   " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# Test 1: Network Inspection
Write-Host "`n[Test 1/5] Inspecting Docker Bridge Network & IPAM..." -ForegroundColor Yellow
$netJson = docker network inspect docker_cyber_lab_net 2>$null
if (-not $netJson) {
    $netJson = docker network inspect cyber_lab_net 2>$null
}
if ($netJson) {
    Write-Host "  [PASSED] Dedicated bridge network detected." -ForegroundColor Green
} else {
    Write-Host "  [FAILED] Bridge network not found." -ForegroundColor Red
}

# Test 2: IP Addresses
Write-Host "`n[Test 2/5] Verifying Container Static IPs (eth0)..." -ForegroundColor Yellow
$genIp = (docker exec generator-node ip -4 addr show eth0) | Select-String -Pattern 'inet (192\.168\.10\.\d+)' | ForEach-Object { $_.Matches.Groups[1].Value }
$colIp = (docker exec collector-node ip -4 addr show eth0) | Select-String -Pattern 'inet (192\.168\.10\.\d+)' | ForEach-Object { $_.Matches.Groups[1].Value }
Write-Host "  • generator-node IP : $genIp"
Write-Host "  • collector-node IP : $colIp"
if ($genIp -eq "192.168.10.10" -and $colIp -eq "192.168.10.20") {
    Write-Host "  [PASSED] Static IP addresses matched." -ForegroundColor Green
} else {
    Write-Host "  [FAILED] Static IP mismatch." -ForegroundColor Red
}

# Test 3: Loopback Aliases
Write-Host "`n[Test 3/5] Verifying Virtual Loopback Aliases (lo:0)..." -ForegroundColor Yellow
$genLo = docker exec generator-node ip -4 addr show lo
if ($genLo -match "192.168.10.100") {
    Write-Host "  [PASSED] Generator lo:0 alias active (192.168.10.100)." -ForegroundColor Green
} else {
    Write-Host "  [WARNING] Generator lo:0 alias not configured." -ForegroundColor Yellow
}

# Test 4: Intra-Sandbox Ping
Write-Host "`n[Test 4/5] Testing Intra-Sandbox ICMP Ping (generator -> collector)..." -ForegroundColor Yellow
$pingRes = docker exec generator-node ping -c 2 -W 2 192.168.10.20
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [PASSED] Successful ICMP ping reachability (192.168.10.10 -> 192.168.10.20)." -ForegroundColor Green
} else {
    Write-Host "  [FAILED] Intra-sandbox ping failed." -ForegroundColor Red
}

# Test 5: Scapy & Raw Socket Probe
Write-Host "`n[Test 5/6] Testing Scapy Raw Socket Health Probe..." -ForegroundColor Yellow
docker exec generator-node python3 /app/verify_phase1.py
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [PASSED] Phase 1 Python Scapy verification passed." -ForegroundColor Green
} else {
    Write-Host "  [FAILED] Python Scapy verification failed." -ForegroundColor Red
}

# Test 6: External Egress Leak Prevention (Host Protection Test)
Write-Host "`n[Test 6/6] Verifying External Leak Resistance (Anti-Exfiltration Policy)..." -ForegroundColor Yellow
$leakRes = docker exec generator-node ping -c 1 -W 2 8.8.8.8 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [PASSED] Outbound public ping strictly dropped/blocked (Zero external leak confirmed)." -ForegroundColor Green
} else {
    Write-Host "  [SECURITY ALERT] Traffic escaped sandbox to public WAN! Review internal: true and iptables." -ForegroundColor Red
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " [SUMMARY] PHASE 1 NETWORK VERIFICATION COMPLETE                      " -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan

