import type { Metadata } from "next";
import EtlButton from "./EtlButton";
import TrafficTester from "./TrafficTester";

export const metadata: Metadata = { title: "NTRO Threat Dashboard" };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface LogRecord {
  source_ip: string;
  destination_ip: string;
  protocol: string;
  packet_count: number;
  total_bytes: number;
  label_name?: string;
  is_l7_malicious: boolean;
  l7_threat_type: string | null;
  matched_signatures: string[];
  etl_processed_at: string;
}

interface ApiResponse {
  total_records: number;
  malicious_count: number;
  logs: LogRecord[];
}

// ---------------------------------------------------------------------------
// Data fetcher — runs server-side on every request (no-store = always fresh)
// ---------------------------------------------------------------------------
async function fetchLogs(): Promise<ApiResponse> {
  try {
    const res = await fetch("http://127.0.0.1:8000/api/logs?limit=50", {
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  } catch {
    return { total_records: 0, malicious_count: 0, logs: [] };
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------
function StatCard({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent: string;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <p className="text-xs font-medium text-slate-400 uppercase tracking-widest mb-1">
        {label}
      </p>
      <p className={`text-4xl font-extrabold ${accent}`}>{value}</p>
    </div>
  );
}

function StatusBadge({ malicious }: { malicious: boolean }) {
  return malicious ? (
    <span className="inline-flex items-center gap-1.5 bg-red-950 text-red-400 border border-red-800 text-xs px-2.5 py-1 rounded-md font-semibold">
      <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
      Malicious
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 bg-emerald-950 text-emerald-400 border border-emerald-800 text-xs px-2.5 py-1 rounded-md font-semibold">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
      Normal
    </span>
  );
}

function SignaturePills({ sigs }: { sigs: string[] }) {
  if (!sigs.length) return <span className="text-slate-600">—</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {sigs.map((s, i) => (
        <span
          key={i}
          className="bg-amber-950 text-amber-300 border border-amber-800 text-xs px-2 py-0.5 rounded font-mono"
        >
          {s.split(":")[0]}
        </span>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default async function Dashboard() {
  const data = await fetchLogs();
  const normalCount = data.total_records - data.malicious_count;

  return (
    <main className="min-h-screen p-6 md:p-10 font-sans">
      <div className="max-w-7xl mx-auto space-y-8">

        {/* ── Header ── */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-cyan-400">
              NTRO CYBER THREAT DASHBOARD
            </h1>
            <p className="text-sm text-slate-500 mt-0.5">
              Next.js 16 · FastAPI · ETL Pipeline · L7 Signature Engine
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="inline-flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-950 border border-emerald-800 px-3 py-1 rounded-full">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              API LIVE · port 8000
            </span>
            <EtlButton />
          </div>
        </header>

        {/* ── Metric cards ── */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <StatCard label="Total ETL Records" value={data.total_records} accent="text-white" />
          <StatCard label="L7 Threats Detected" value={data.malicious_count} accent="text-red-400" />
          <StatCard label="Clean Flows" value={normalCount} accent="text-emerald-400" />
        </div>

        {/* ── Traffic Tester ── */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
          <div className="px-6 py-4 border-b border-slate-800">
            <h2 className="font-semibold text-slate-200">Manual Traffic Injection Tester</h2>
            <p className="text-xs text-slate-500 mt-0.5">Submit a custom flow to the AI + L7 engine and inspect the live detection result.</p>
          </div>
          <div className="p-6">
            <TrafficTester />
          </div>
        </section>

        {/* ── Log table ── */}
        <section className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
            <h2 className="font-semibold text-slate-200">
              Enriched Flow Records
              <span className="ml-2 text-xs font-normal text-slate-500">
                (last {data.logs.length} of {data.total_records})
              </span>
            </h2>
          </div>

          {data.logs.length === 0 ? (
            <div className="px-6 py-16 text-center text-slate-500 text-sm">
              No ETL records found. Run{" "}
              <code className="text-cyan-400 font-mono">python etl_pipeline.py</code>{" "}
              to populate the pipeline.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm border-collapse">
                <thead>
                  <tr className="bg-slate-950 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800">
                    <th className="px-5 py-3">Source IP</th>
                    <th className="px-5 py-3">Destination IP</th>
                    <th className="px-5 py-3">Proto</th>
                    <th className="px-5 py-3">Pkts</th>
                    <th className="px-5 py-3">Bytes</th>
                    <th className="px-5 py-3">L7 Threat</th>
                    <th className="px-5 py-3">Signatures</th>
                    <th className="px-5 py-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {data.logs.map((log, idx) => (
                    <tr
                      key={idx}
                      className={`transition-colors hover:bg-slate-800/40 ${
                        log.is_l7_malicious ? "bg-red-950/10" : ""
                      }`}
                    >
                      <td className="px-5 py-3 font-mono text-slate-300 whitespace-nowrap">
                        {log.source_ip}
                      </td>
                      <td className="px-5 py-3 font-mono text-slate-300 whitespace-nowrap">
                        {log.destination_ip}
                      </td>
                      <td className="px-5 py-3">
                        <span className="text-xs font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                          {log.protocol}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-slate-400 tabular-nums">
                        {log.packet_count}
                      </td>
                      <td className="px-5 py-3 text-slate-400 tabular-nums">
                        {log.total_bytes.toLocaleString()}
                      </td>
                      <td className="px-5 py-3 text-yellow-400 font-mono text-xs">
                        {log.l7_threat_type ?? (
                          <span className="text-slate-600">—</span>
                        )}
                      </td>
                      <td className="px-5 py-3 max-w-xs">
                        <SignaturePills sigs={log.matched_signatures ?? []} />
                      </td>
                      <td className="px-5 py-3 whitespace-nowrap">
                        <StatusBadge malicious={log.is_l7_malicious} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <footer className="text-center text-xs text-slate-600 pb-4">
          NTRO AI Cyber Threat Detection System · ETL + L7 Inspection Pipeline
        </footer>
      </div>
    </main>
  );
}
