import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-panel p-3 rounded-lg border border-cyan-500/30 text-xs shadow-xl">
        <p className="font-mono font-bold text-cyan-400 mb-1">{`Time: ${label}`}</p>
        <p className="text-emerald-400 font-semibold">{`Normal Traffic: ${payload[0]?.value || 0}`}</p>
        <p className="text-red-400 font-semibold">{`Malicious Threats: ${payload[1]?.value || 0}`}</p>
      </div>
    );
  }
  return null;
};

export default function TrafficChart({ data = [] }) {
  const chartData = data.length > 0 ? data : [
    { time: '14:30', normal: 25, malicious: 2 },
    { time: '14:31', normal: 30, malicious: 5 },
    { time: '14:32', normal: 28, malicious: 1 },
    { time: '14:33', normal: 35, malicious: 8 },
    { time: '14:34', normal: 40, malicious: 3 },
    { time: '14:35', normal: 38, malicious: 12 },
  ];

  return (
    <div className="glass-panel p-5 rounded-xl border border-slate-800 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-base font-bold tracking-wide text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            REAL-TIME TRAFFIC & THREAT VOLUME TRENDS
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Throughput telemetry analysis & anomaly detection timeline
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs font-medium">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-emerald-500/80"></span>
            <span className="text-slate-300">Normal Flow</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded bg-red-500/80"></span>
            <span className="text-slate-300">Malicious Threat</span>
          </div>
        </div>
      </div>

      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorNormal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10B981" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#10B981" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorMalicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.6} />
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
            <XAxis dataKey="time" stroke="#6B7280" fontSize={11} tickLine={false} />
            <YAxis stroke="#6B7280" fontSize={11} tickLine={false} />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="normal"
              stroke="#10B981"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorNormal)"
            />
            <Area
              type="monotone"
              dataKey="malicious"
              stroke="#EF4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorMalicious)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
