import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, Play, Server, Clock } from 'lucide-react';

export default function Navbar({ isDemo = true, lastAuditTime, hostname = 'localhost' }) {
  const navigate = useNavigate();

  return (
    <header className="h-16 bg-[#0d121f]/90 border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      {/* Left: Active Host Info */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs">
          <Server className="w-4 h-4 text-slate-400" />
          <span className="text-slate-400 font-medium">Target Host:</span>
          <span className="font-mono font-bold text-white bg-slate-800/80 px-2 py-0.5 rounded border border-slate-700/60">
            {hostname}
          </span>
        </div>

        {/* Mode Indicator Badge */}
        {isDemo ? (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
            DEMO MODE (SIMULATED)
          </span>
        ) : (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            LIVE SYSTEM AUDIT
          </span>
        )}
      </div>

      {/* Right: Last Audit Timestamp & Trigger */}
      <div className="flex items-center gap-4">
        {lastAuditTime && (
          <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400">
            <Clock className="w-3.5 h-3.5" />
            <span>Last Audit: {new Date(lastAuditTime).toLocaleTimeString()}</span>
          </div>
        )}

        <button
          onClick={() => navigate('/audit')}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition shadow-lg shadow-blue-900/30 active:scale-95"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>New Audit</span>
        </button>
      </div>
    </header>
  );
}
