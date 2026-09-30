import React from 'react';
import { CheckCircle2, XCircle, AlertTriangle, HelpCircle } from 'lucide-react';

const STATUS_CONFIG = {
  PASS: {
    label: 'PASS',
    style: 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60',
    icon: CheckCircle2,
  },
  FAIL: {
    label: 'FAIL',
    style: 'bg-red-950/70 text-red-400 border-red-800/60 shadow-[0_0_8px_rgba(239,68,68,0.15)]',
    icon: XCircle,
  },
  WARNING: {
    label: 'WARNING',
    style: 'bg-amber-950/70 text-amber-400 border-amber-800/60',
    icon: AlertTriangle,
  },
  NOT_AVAILABLE: {
    label: 'N/A',
    style: 'bg-slate-900/80 text-slate-400 border-slate-700/80',
    icon: HelpCircle,
  },
};

export default function StatusBadge({ status, showIcon = true, className = '' }) {
  const statKey = (status || 'NOT_AVAILABLE').toUpperCase();
  const config = STATUS_CONFIG[statKey] || STATUS_CONFIG.NOT_AVAILABLE;
  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-semibold uppercase border ${config.style} ${className}`}
    >
      {showIcon && <Icon className="w-3.5 h-3.5" />}
      {config.label}
    </span>
  );
}
