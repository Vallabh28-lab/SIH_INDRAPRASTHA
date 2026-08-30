"use client";

import { useState } from "react";

export default function EtlButton() {
  const [loading, setLoading] = useState(false);
  const [msg, setMsg]         = useState<{ text: string; ok: boolean } | null>(null);

  // Uses Railway ETL service when NEXT_PUBLIC_ETL_URL is set, falls back to local proxy
  const ETL_URL = process.env.NEXT_PUBLIC_ETL_URL
    ? `${process.env.NEXT_PUBLIC_ETL_URL}/run`
    : "/api/trigger-etl";

  const run = async () => {
    setLoading(true);
    setMsg(null);
    try {
      const res    = await fetch(ETL_URL, { method: "POST" });
      const result = await res.json();
      // Normalise response shape between Railway /run and local /api/trigger-etl
      const ok      = result.status === "success";
      const message = result.message
        ?? `Processed ${result.records_processed} records · ${result.l7_threats_detected} L7 threats`;
      setMsg({ text: message, ok });
      if (ok) setTimeout(() => window.location.reload(), 1200);
    } catch {
      setMsg({ text: "Failed to reach ETL service.", ok: false });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center gap-3">
      {msg && (
        <span
          className={`text-xs font-mono px-3 py-1 rounded-full border ${
            msg.ok
              ? "text-emerald-400 bg-emerald-950 border-emerald-800"
              : "text-red-400 bg-red-950 border-red-800"
          }`}
        >
          {msg.text}
        </span>
      )}
      <button
        onClick={run}
        disabled={loading}
        className="inline-flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm font-semibold px-4 py-2 rounded-lg shadow transition-colors"
      >
        {loading ? (
          <>
            <span className="w-3 h-3 rounded-full border-2 border-white border-t-transparent animate-spin" />
            Running ETL…
          </>
        ) : (
          <>▶ Run ETL Pipeline</>
        )}
      </button>
    </div>
  );
}
