"use client";

import { useState } from "react";

interface DetectionResult {
  status?: string;
  prediction?: string;
  prediction_label?: string;
  confidence?: number;
  anomaly_score?: number;
  is_malicious?: boolean;
  l7_analysis?: {
    is_l7_malicious: boolean;
    l7_threat_type: string | null;
    matched_signatures: string[];
  };
  audit_id?: string;
  error?: string;
}

const PRESETS = [
  { label: "Normal",        source_ip: "192.168.1.10", uri_path: "/index.html",                               packet_count: 50,   total_bytes: 1500   },
  { label: "SQLi",          source_ip: "10.0.4.88",    uri_path: "/api/search?q=UNION SELECT * FROM users--", packet_count: 150,  total_bytes: 4500   },
  { label: "XSS",           source_ip: "172.16.0.55",  uri_path: "/post?text=<script>alert(1)</script>",      packet_count: 80,   total_bytes: 2400   },
  { label: "Path Traversal",source_ip: "10.10.10.5",   uri_path: "/file?path=../../etc/passwd",               packet_count: 30,   total_bytes: 900    },
  { label: "SYN Flood",     source_ip: "203.0.113.99", uri_path: "",                                          packet_count: 5000, total_bytes: 250000 },
];

export default function TrafficTester() {
  const [form, setForm] = useState({
    source_ip:      "192.168.1.50",
    destination_ip: "10.0.0.1",
    protocol:       "TCP",
    packet_count:   150,
    total_bytes:    4500,
    uri_path:       "/api/search?q=UNION SELECT * FROM users",
    body_payload:   "",
  });
  const [result, setResult]   = useState<DetectionResult | null>(null);
  const [loading, setLoading] = useState(false);

  const applyPreset = (p: (typeof PRESETS)[0]) =>
    setForm(f => ({ ...f, source_ip: p.source_ip, uri_path: p.uri_path, packet_count: p.packet_count, total_bytes: p.total_bytes }));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/traffic", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, packet_count: Number(form.packet_count), total_bytes: Number(form.total_bytes) }),
      });
      setResult(await res.json());
    } catch {
      setResult({ error: "Failed to connect to backend API." });
    } finally {
      setLoading(false);
    }
  };

  const isMalicious = result?.is_malicious || result?.l7_analysis?.is_l7_malicious;

  return (
    <div className="space-y-5">
      {/* Form */}
      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 p-6 rounded-xl space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h2 className="font-semibold text-slate-200">Simulate Custom Traffic Packet</h2>
          <div className="flex flex-wrap gap-2">
            {PRESETS.map(p => (
              <button key={p.label} type="button" onClick={() => applyPreset(p)}
                className="text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-2.5 py-1 rounded transition-colors">
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {(["source_ip", "destination_ip"] as const).map(field => (
            <div key={field}>
              <label className="block text-xs uppercase font-mono text-slate-400 mb-1">
                {field === "source_ip" ? "Source IP" : "Destination IP"}
              </label>
              <input type="text" required value={form[field]}
                onChange={e => setForm({ ...form, [field]: e.target.value })}
                className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-600" />
            </div>
          ))}
          <div>
            <label className="block text-xs uppercase font-mono text-slate-400 mb-1">Packet Count</label>
            <input type="number" value={form.packet_count}
              onChange={e => setForm({ ...form, packet_count: e.target.value as unknown as number })}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-600" />
          </div>
          <div>
            <label className="block text-xs uppercase font-mono text-slate-400 mb-1">Total Bytes</label>
            <input type="number" value={form.total_bytes}
              onChange={e => setForm({ ...form, total_bytes: e.target.value as unknown as number })}
              className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-600" />
          </div>
        </div>

        <div>
          <label className="block text-xs uppercase font-mono text-slate-400 mb-1">URI Path / L7 Payload</label>
          <input type="text" value={form.uri_path} placeholder="/api/search?q=..."
            onChange={e => setForm({ ...form, uri_path: e.target.value })}
            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-600" />
        </div>

        <div>
          <label className="block text-xs uppercase font-mono text-slate-400 mb-1">Body Payload (optional)</label>
          <input type="text" value={form.body_payload} placeholder="{'q': 'admin OR 1=1--'}"
            onChange={e => setForm({ ...form, body_payload: e.target.value })}

            className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-cyan-600" />
        </div>

        <button type="submit" disabled={loading}
          className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold py-2.5 rounded-lg transition-colors">
          {loading
            ? <span className="inline-flex items-center gap-2 justify-center">
                <span className="w-3 h-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
                Inspecting Traffic…
              </span>
            : "Analyze & Detect Threat"}
        </button>
      </form>

      {/* Result card */}
      {result && (
        <div className={`border p-6 rounded-xl font-mono text-sm space-y-4 ${
          result.error ? "bg-slate-900 border-slate-700"
            : isMalicious ? "bg-red-950/20 border-red-800"
            : "bg-emerald-950/20 border-emerald-800"
        }`}>
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider">Detection Result</h3>
            {!result.error && (
              <span className={`text-sm font-bold px-3 py-1 rounded-md ${isMalicious ? "bg-red-900 text-red-300" : "bg-emerald-900 text-emerald-300"}`}>
                {isMalicious ? "⚠ MALICIOUS / FAKE" : "✓ AUTHENTIC / NORMAL"}
              </span>
            )}
          </div>

          {result.error ? (
            <p className="text-red-400">{result.error}</p>
          ) : (
            <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-xs">
              <Row label="Prediction"    value={result.prediction_label ?? result.prediction ?? "—"} color="text-cyan-300" />
              <Row label="Confidence"    value={result.confidence != null ? `${(result.confidence * 100).toFixed(1)}%` : "—"} />
              <Row label="Anomaly Score" value={result.anomaly_score?.toFixed(4) ?? "—"} />
              <Row label="Audit ID"      value={result.audit_id ?? "—"} color="text-slate-400" />
              {result.l7_analysis && (
                <>
                  <Row label="L7 Threat Type"
                    value={result.l7_analysis.l7_threat_type ?? "None"}
                    color={result.l7_analysis.l7_threat_type ? "text-yellow-400" : "text-slate-500"} />
                  <div className="col-span-2">
                    <span className="text-slate-500">Matched Signatures: </span>
                    {result.l7_analysis.matched_signatures.length
                      ? result.l7_analysis.matched_signatures.map((s, i) => (
                          <span key={i} className="inline-block bg-amber-950 text-amber-300 border border-amber-800 text-xs px-2 py-0.5 rounded mr-1 mt-1">
                            {s.split(":")[0]}
                          </span>
                        ))
                      : <span className="text-slate-600">—</span>}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, color = "text-slate-200" }: { label: string; value: string; color?: string }) {
  return (
    <div>
      <span className="text-slate-500">{label}: </span>
      <span className={color}>{value}</span>
    </div>
  );
}
