"use client";

import { useState } from "react";

export default function EtlButton() {
  const [loading, setLoading] = useState(false);
  const [msg, setMsg]         = useState<{ text: string; ok: boolean } | null>(null);

  const run = async () => {
    setLoading(true);
    setMsg(null);
    try {
      const res    = await fetch("/api/trigger-etl", { method: "POST" });
      const result = await res.json();
      setMsg({ text: result.message, ok: result.status === "success" });
      if (result.status === "success") {
        setTimeout(() => window.location.reload(), 1200);
      }
    } catch {
      setMsg({ text: "Failed to reach API.", ok: false });
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
