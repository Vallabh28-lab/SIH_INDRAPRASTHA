import React from 'react';
import { Activity, ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react';

export default function MetricsCards({ metrics }) {
  const cards = [
    {
      title: 'TOTAL FLOWS',
      value: metrics?.total_flows || 0,
      icon: Activity,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20',
      subtitle: 'Real-time telemetry stream',
    },
    {
      title: 'THREATS DETECTED',
      value: metrics?.threats_detected || 0,
      icon: ShieldAlert,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      glow: 'glow-red',
      subtitle: 'Flagged by ML & XAI',
    },
    {
      title: 'HIGH RISK ALERTS',
      value: metrics?.high_risk || 0,
      icon: AlertTriangle,
      color: 'text-amber-400',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30',
      subtitle: 'Anomaly score > 0.70',
    },
    {
      title: 'NORMAL TRAFFIC',
      value: metrics?.normal_traffic || 0,
      icon: ShieldCheck,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20',
      subtitle: 'Verified benign sessions',
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {cards.map((card, idx) => {
        const IconComponent = card.icon;
        return (
          <div
            key={idx}
            className={`glass-panel p-5 rounded-xl border ${card.borderColor} ${card.glow || ''} transition-all duration-300 hover:scale-[1.02]`}
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold tracking-wider text-slate-400 uppercase">
                  {card.title}
                </p>
                <h3 className="text-3xl font-bold font-mono mt-2 text-white">
                  {card.value.toLocaleString()}
                </h3>
              </div>
              <div className={`p-3 rounded-lg ${card.bgColor} ${card.color}`}>
                <IconComponent className="w-6 h-6" />
              </div>
            </div>
            <div className="mt-3 flex items-center text-xs text-slate-400">
              <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-ping mr-2"></span>
              {card.subtitle}
            </div>
          </div>
        );
      })}
    </div>
  );
}
