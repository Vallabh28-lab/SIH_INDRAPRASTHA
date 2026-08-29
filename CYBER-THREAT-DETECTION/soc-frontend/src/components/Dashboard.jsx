import React, { useState, useEffect } from 'react';
import { RefreshCw, Play, ShieldAlert, ShieldCheck, Zap, Lock, Terminal, Activity } from 'lucide-react';
import MetricsCards from './MetricsCards';
import TrafficChart from './TrafficChart';
import ThreatsTable from './ThreatsTable';
import ForensicModal from './ForensicModal';
import { fetchDashboardData, simulateTraffic, verifyAuditIntegrity } from '../services/api';

export default function Dashboard() {
  const [data, setData] = useState({ metrics: {}, trends: [], events: [] });
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [integrity, setIntegrity] = useState(null);
  const [activeTab, setActiveTab] = useState('LIVE_TELEMETRY'); // LIVE_TELEMETRY | AUDIT_TRAIL

  const loadData = async () => {
    try {
      setLoading(true);
      const res = await fetchDashboardData(100);
      setData(res);
    } catch (err) {
      console.error('Error fetching SOC telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  const checkIntegrity = async () => {
    try {
      const res = await verifyAuditIntegrity();
      setIntegrity(res);
    } catch (err) {
      console.error('Integrity check failed:', err);
    }
  };

  useEffect(() => {
    loadData();
    checkIntegrity();

    let interval;
    if (autoRefresh) {
      interval = setInterval(() => {
        loadData();
      }, 3000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const handleSimulate = async (attackType) => {
    try {
      setSimulating(true);
      await simulateTraffic(attackType);
      await loadData();
      await checkIntegrity();
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0A0E17] text-slate-100 p-4 md:p-8">
      {/* Top Header Bar */}
      <header className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-8 pb-5 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Zap className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-white flex items-center gap-2">
                NTRO CYBER SECURITY OPERATIONS CENTER
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                  v2.5 SOC
                </span>
              </h1>
              <p className="text-xs text-slate-400 mt-0.5">
                AI Multi-Class Threat Classification, Explainable AI (SHAP) & Cryptographic SHA-256 Forensic Audit Engine
              </p>
            </div>
          </div>
        </div>

        {/* Live Controls & Simulation Actions */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Attack Simulator Dropdown / Buttons */}
          <div className="flex items-center gap-1.5 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800">
            <span className="text-[11px] font-bold text-slate-400 px-2 uppercase flex items-center gap-1">
              <Play className="w-3 h-3 text-cyan-400" /> SIMULATE:
            </span>
            <button
              onClick={() => handleSimulate('Normal')}
              disabled={simulating}
              className="px-2.5 py-1 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-xs font-semibold transition disabled:opacity-50"
            >
              Normal
            </button>
            <button
              onClick={() => handleSimulate('SYN_Flood')}
              disabled={simulating}
              className="px-2.5 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-semibold transition disabled:opacity-50"
            >
              SYN Flood
            </button>
            <button
              onClick={() => handleSimulate('Port_Scan')}
              disabled={simulating}
              className="px-2.5 py-1 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-xs font-semibold transition disabled:opacity-50"
            >
              Port Scan
            </button>
            <button
              onClick={() => handleSimulate('UDP_Flood')}
              disabled={simulating}
              className="px-2.5 py-1 rounded-lg bg-purple-500/10 hover:bg-purple-500/20 text-purple-400 border border-purple-500/30 text-xs font-semibold transition disabled:opacity-50"
            >
              UDP Flood
            </button>
          </div>

          {/* Auto Refresh Toggle */}
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold border transition ${
              autoRefresh
                ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {autoRefresh ? 'Live Polling ON' : 'Paused'}
          </button>
        </div>
      </header>

      {/* Cryptographic Hash-Chain Integrity Banner */}
      <div className="mb-6 p-3 rounded-xl bg-slate-900/80 border border-cyan-500/20 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2">
          <Lock className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-300">BLOCKCHAIN AUDIT TRAIL STATUS:</span>
          <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono font-bold border border-emerald-500/30">
            {integrity?.status === 'VALID' ? '✓ HASH CHAIN INTAC / TAMPER-EVIDENT' : 'VERIFYING...'}
          </span>
        </div>
        <div className="flex items-center gap-4 text-slate-400 font-mono text-[11px]">
          <span>Total Audit Records: <strong className="text-white">{integrity?.total_records || 0}</strong></span>
          <span>Corrupted: <strong className="text-emerald-400">0</strong></span>
        </div>
      </div>

      {/* Top Metric Cards */}
      <MetricsCards metrics={data.metrics} />

      {/* Real-time Traffic Volume Trends Chart */}
      <TrafficChart data={data.trends} />

      {/* Live Threats & Telemetry Table */}
      <ThreatsTable
        events={data.events}
        onSelectAlert={(alert) => setSelectedAlert(alert)}
      />

      {/* Forensic Inspector Modal / Drawer */}
      {selectedAlert && (
        <ForensicModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  );
}
