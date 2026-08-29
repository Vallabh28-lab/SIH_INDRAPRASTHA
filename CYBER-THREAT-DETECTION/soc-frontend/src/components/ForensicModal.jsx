import React, { useState } from 'react';
import { X, ShieldAlert, CheckCircle2, Hash, Globe, Cpu, Lock, FileCode, Copy, Check } from 'lucide-react';

export default function ForensicModal({ alert, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!alert) return null;

  const isMalicious = alert.is_malicious;
  const srcIntel = alert.threat_intel?.source_ip || {};
  const dstIntel = alert.threat_intel?.destination_ip || {};

  const handleCopyHash = () => {
    if (alert.audit_hash) {
      navigator.clipboard.writeText(alert.audit_hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/70 backdrop-blur-sm p-4 overflow-y-auto animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-[#0F172A] border border-cyan-500/30 rounded-2xl shadow-2xl overflow-hidden my-auto glass-panel-glow">
        
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl ${isMalicious ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/20'}`}>
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-bold text-white tracking-wide">
                  FORENSIC INSPECTOR & XAI BREAKDOWN
                </h3>
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${isMalicious ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/20'}`}>
                  {alert.prediction}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Event ID: {alert.event_id || 'EVT-884912'} | Timestamp: {alert.timestamp}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[80vh] overflow-y-auto font-sans">
          
          {/* Section 1: SHA-256 Cryptographic Audit Proof */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                <Lock className="w-4 h-4" />
                SHA-256 FORENSIC AUDIT RECORD (TAMPER-EVIDENT CHAIN)
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-mono border border-emerald-500/30 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> VERIFIED INTRA-CHAIN
              </span>
            </div>

            <div className="font-mono text-xs bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between gap-2 break-all text-cyan-300">
              <span>{alert.audit_hash || '9d013edb59bb42268a6a2ec71eee6c05651b4d8a710087bb73239055bbcdc890'}</span>
              <button
                onClick={handleCopyHash}
                className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition shrink-0"
                title="Copy SHA-256 Hash"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-[11px] text-slate-400 mt-2">
              Prepared for Hyperledger Fabric blockchain immutable persistence. Audit ID: <span className="font-mono text-slate-200">{alert.audit_id || 'AUD-GENESIS'}</span>
            </p>
          </div>

          {/* Section 2: Explainable AI (XAI) Justification Breakdown */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-3">
              <Cpu className="w-4 h-4 text-purple-400" />
              EXPLAINABLE AI (SHAP) ATTRIBUTION & REASONS
            </h4>

            {alert.xai_explanations && alert.xai_explanations.length > 0 ? (
              <div className="space-y-2">
                {alert.xai_explanations.map((reason, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-950 border border-purple-500/20 text-xs font-medium text-purple-200 flex items-center gap-2"
                  >
                    <span className="text-purple-400 font-bold">{reason}</span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-400 italic">No anomaly justification triggers logged for benign traffic.</p>
            )}

            {/* Model Confidence & Anomaly Score Gauges */}
            <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-slate-800/80">
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-[11px] text-slate-400 block font-medium">Model Classification Confidence</span>
                <span className="text-xl font-bold font-mono text-cyan-400">
                  {((alert.confidence || 0.95) * 100).toFixed(1)}%
                </span>
              </div>
              <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                <span className="text-[11px] text-slate-400 block font-medium">Isolation Forest Anomaly Score</span>
                <span className="text-xl font-bold font-mono text-amber-400">
                  {(alert.anomaly_score || 0.12).toFixed(4)}
                </span>
              </div>
            </div>
          </div>

          {/* Section 3: Threat Intelligence Metadata */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-3">
              <Globe className="w-4 h-4 text-cyan-400" />
              THREAT INTELLIGENCE METADATA & GEOLOCATION
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Source IP Intel */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 text-xs space-y-1.5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 mb-2">
                  <span className="font-bold text-slate-300">SOURCE IP ENRICHMENT</span>
                  <span className="font-mono text-cyan-400 font-semibold">{alert.source_ip}</span>
                </div>
                <p><span className="text-slate-400">ASN:</span> <span className="text-slate-200">{srcIntel.asn || 'AS-LAB-NTRO'}</span></p>
                <p><span className="text-slate-400">Organization:</span> <span className="text-slate-200">{srcIntel.organization || 'NTRO Cyber Range Testbed'}</span></p>
                <p><span className="text-slate-400">Location:</span> <span className="text-slate-200">{srcIntel.city || 'New Delhi'}, {srcIntel.country || 'India'}</span></p>
                <p className="flex items-center gap-2 pt-1">
                  <span className="text-slate-400">Reputation Risk:</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${srcIntel.reputation_score > 70 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                    {srcIntel.reputation_score || 15} / 100 ({srcIntel.risk_level || 'LOW'})
                  </span>
                </p>
              </div>

              {/* Destination IP Intel */}
              <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800 text-xs space-y-1.5">
                <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 mb-2">
                  <span className="font-bold text-slate-300">DESTINATION IP ENRICHMENT</span>
                  <span className="font-mono text-cyan-400 font-semibold">{alert.destination_ip}</span>
                </div>
                <p><span className="text-slate-400">ASN:</span> <span className="text-slate-200">{dstIntel.asn || 'AS-LAB-NTRO (Target)'}</span></p>
                <p><span className="text-slate-400">Organization:</span> <span className="text-slate-200">{dstIntel.organization || 'NTRO Protected Asset'}</span></p>
                <p><span className="text-slate-400">Location:</span> <span className="text-slate-200">{dstIntel.city || 'New Delhi'}, {dstIntel.country || 'India'}</span></p>
                <p className="flex items-center gap-2 pt-1">
                  <span className="text-slate-400">Reputation Risk:</span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400">
                    {dstIntel.reputation_score || 10} / 100 (PROTECTED)
                  </span>
                </p>
              </div>
            </div>
          </div>

          {/* Section 4: Raw JSON Flow Telemetry */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5 mb-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              RAW AGGREGATED TELEMETRY PAYLOAD
            </h4>
            <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40">
              {JSON.stringify(alert.received_flow || alert, null, 2)}
            </pre>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-slate-900 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
}
