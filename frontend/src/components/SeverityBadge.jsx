import React from 'react';

const SEVERITY_STYLES = {
  CRITICAL: 'bg-red-950/80 text-red-400 border-red-800/60 shadow-[0_0_10px_rgba(239,68,68,0.2)]',
  HIGH: 'bg-orange-950/80 text-orange-400 border-orange-800/60',
  MEDIUM: 'bg-amber-950/80 text-amber-400 border-amber-800/60',
  LOW: 'bg-blue-950/80 text-blue-400 border-blue-800/60',
  INFO: 'bg-slate-900 text-slate-400 border-slate-700',
};

export default function SeverityBadge({ severity, className = '' }) {
  const sevKey = (severity || 'INFO').toUpperCase();
  const style = SEVERITY_STYLES[sevKey] || SEVERITY_STYLES.INFO;

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold tracking-wider uppercase border ${style} ${className}`}
    >
      {sevKey}
    </span>
  );
}
