import React from 'react';
import { CheckCircle2, Loader2, Circle } from 'lucide-react';

export const AUDIT_STAGES = [
  { id: 'system', name: 'System Information' },
  { id: 'users', name: 'Users & Groups' },
  { id: 'passwords', name: 'Password Policy' },
  { id: 'ssh', name: 'SSH Configuration' },
  { id: 'permissions', name: 'File Permissions' },
  { id: 'services', name: 'Running Services' },
  { id: 'network', name: 'Listening Ports' },
  { id: 'firewall', name: 'Firewall Status' },
  { id: 'updates', name: 'Security Updates' },
  { id: 'cron', name: 'Cron Tasks' },
  { id: 'kernel', name: 'Kernel Hardening' },
];

export default function AuditProgressBar({ currentStep, isRunning }) {
  return (
    <div className="bg-[#111726] border border-slate-800 rounded-xl p-5 shadow-xl">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          {isRunning ? (
            <Loader2 className="w-5 h-5 text-blue-400 animate-spin" />
          ) : (
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          )}
          <h3 className="font-bold text-sm text-white">
            {isRunning ? 'Executing Defensive Security Audit...' : 'Audit Run Completed'}
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Step {Math.min(currentStep + 1, AUDIT_STAGES.length)} of {AUDIT_STAGES.length}
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
        {AUDIT_STAGES.map((stage, idx) => {
          const isDone = idx < currentStep;
          const isCurrent = idx === currentStep && isRunning;
          const isPending = idx > currentStep;

          let badgeColor = 'bg-slate-900/60 border-slate-800 text-slate-500';
          if (isDone) {
            badgeColor = 'bg-emerald-950/30 border-emerald-800/40 text-emerald-400';
          } else if (isCurrent) {
            badgeColor = 'bg-blue-950/40 border-blue-600/60 text-blue-300 ring-1 ring-blue-500/50 animate-pulse';
          }

          return (
            <div
              key={stage.id}
              className={`flex items-center gap-2 p-2.5 rounded-lg border text-xs font-medium transition-all ${badgeColor}`}
            >
              {isDone && <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />}
              {isCurrent && <Loader2 className="w-4 h-4 text-blue-400 animate-spin flex-shrink-0" />}
              {isPending && <Circle className="w-4 h-4 text-slate-600 flex-shrink-0" />}
              <span className="truncate">{stage.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
