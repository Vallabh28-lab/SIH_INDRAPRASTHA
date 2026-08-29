import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Eye, Hash, Search, Filter } from 'lucide-react';

export default function ThreatsTable({ events = [], onSelectAlert }) {
  const [filter, setFilter] = useState('ALL');
  const [search, setSearch] = useState('');

  const filteredEvents = events.filter((e) => {
    if (filter === 'MALICIOUS' && !e.is_malicious) return false;
    if (filter === 'NORMAL' && e.is_malicious) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        e.source_ip?.toLowerCase().includes(q) ||
        e.destination_ip?.toLowerCase().includes(q) ||
        e.prediction?.toLowerCase().includes(q) ||
        e.protocol?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="glass-panel p-5 rounded-xl border border-slate-800">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
        <div>
          <h2 className="text-base font-bold tracking-wide text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-400" />
            LIVE TELEMETRY & SECURITY ALERTS TABLE
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Click any alert row to launch Forensic Inspector XAI drawer
          </p>
        </div>

        {/* Filter controls */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, classification..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-slate-900/80 border border-slate-700/60 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48"
            />
          </div>

          <div className="flex rounded-lg bg-slate-900/80 p-0.5 border border-slate-700/60 text-xs">
            <button
              onClick={() => setFilter('ALL')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filter === 'ALL' ? 'bg-cyan-500/20 text-cyan-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('MALICIOUS')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filter === 'MALICIOUS' ? 'bg-red-500/20 text-red-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              🔴 Malicious
            </button>
            <button
              onClick={() => setFilter('NORMAL')}
              className={`px-3 py-1 rounded-md font-medium transition ${
                filter === 'NORMAL' ? 'bg-emerald-500/20 text-emerald-400 font-semibold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              🟢 Normal
            </button>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-sans">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Source IP</th>
              <th className="py-3 px-4">Destination IP</th>
              <th className="py-3 px-4">Protocol</th>
              <th className="py-3 px-4">Classification</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Anomaly Score</th>
              <th className="py-3 px-4">SHA-256 Audit Hash</th>
              <th className="py-3 px-4 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan="10" className="py-8 text-center text-slate-500">
                  No telemetry flow records match the criteria.
                </td>
              </tr>
            ) : (
              filteredEvents.map((evt, idx) => {
                const isMal = evt.is_malicious;
                return (
                  <tr
                    key={evt.event_id || idx}
                    onClick={() => onSelectAlert(evt)}
                    className="hover:bg-slate-800/40 transition cursor-pointer group"
                  >
                    <td className="py-3 px-4">
                      {isMal ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/10 text-red-400 border border-red-500/30 font-semibold text-[11px]">
                          <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                          Malicious
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold text-[11px]">
                          <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                          Normal
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400">
                      {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : '14:32:00'}
                    </td>

                    <td className="py-3 px-4 font-mono font-medium text-slate-200">
                      {evt.source_ip}
                      <span className="text-slate-500 text-[10px] block">Port: {evt.source_port || 54321}</span>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-300">
                      {evt.destination_ip}
                      <span className="text-slate-500 text-[10px] block">Port: {evt.destination_port || 80}</span>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px]">
                        {evt.protocol}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-semibold text-slate-200">
                      <span className={isMal ? 'text-red-400' : 'text-emerald-400'}>
                        {evt.prediction}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono">
                      <div className="flex items-center gap-2">
                        <div className="w-12 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full ${isMal ? 'bg-red-500' : 'bg-emerald-500'}`}
                            style={{ width: `${(evt.confidence || 0.9) * 100}%` }}
                          ></div>
                        </div>
                        <span className="text-slate-300">
                          {((evt.confidence || 0.9) * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-300">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          (evt.anomaly_score || 0) > 0.7
                            ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                            : (evt.anomaly_score || 0) > 0.5
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/20'
                        }`}
                      >
                        {(evt.anomaly_score || 0.1).toFixed(4)}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {evt.audit_hash ? (
                        <span className="inline-flex items-center gap-1 text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                          <Hash className="w-3 h-3" />
                          {evt.audit_hash.substring(0, 12)}...
                        </span>
                      ) : (
                        <span className="text-slate-600">N/A</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(evt);
                        }}
                        className="p-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 transition border border-cyan-500/30 group-hover:scale-105"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
