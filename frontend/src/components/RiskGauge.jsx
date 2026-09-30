import React from 'react';
import { ShieldAlert, ShieldCheck, AlertOctagon, AlertTriangle } from 'lucide-react';

export default function RiskGauge({ score = 0, level = 'LOW RISK' }) {
  // Determine color palette based on 0-100 scale
  let color = '#10b981'; // green
  let textColor = 'text-emerald-400';
  let borderColor = 'border-emerald-500/30';
  let bgColor = 'bg-emerald-950/20';
  let Icon = ShieldCheck;

  if (score >= 80) {
    color = '#ef4444'; // red
    textColor = 'text-red-400';
    borderColor = 'border-red-500/40';
    bgColor = 'bg-red-950/30';
    Icon = AlertOctagon;
  } else if (score >= 60) {
    color = '#f97316'; // orange
    textColor = 'text-orange-400';
    borderColor = 'border-orange-500/40';
    bgColor = 'bg-orange-950/30';
    Icon = ShieldAlert;
  } else if (score >= 40) {
    color = '#eab308'; // yellow
    textColor = 'text-amber-400';
    borderColor = 'border-amber-500/40';
    bgColor = 'bg-amber-950/30';
    Icon = AlertTriangle;
  } else if (score >= 20) {
    color = '#3b82f6'; // blue
    textColor = 'text-blue-400';
    borderColor = 'border-blue-500/40';
    bgColor = 'bg-blue-950/30';
    Icon = ShieldCheck;
  }

  // Circular gauge calculations
  const radius = 62;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={`flex flex-col items-center justify-center p-6 rounded-xl border ${borderColor} ${bgColor} relative overflow-hidden backdrop-blur-sm`}>
      <div className="relative w-40 h-40 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90">
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke="#1e293b"
            strokeWidth="12"
            fill="transparent"
          />
          <circle
            cx="80"
            cy="80"
            r={radius}
            stroke={color}
            strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute flex flex-col items-center justify-center text-center">
          <span className={`text-4xl font-extrabold tracking-tight ${textColor}`}>
            {score}
          </span>
          <span className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
            / 100
          </span>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-2">
        <Icon className={`w-5 h-5 ${textColor}`} />
        <span className={`text-sm font-bold tracking-wider uppercase ${textColor}`}>
          {level}
        </span>
      </div>

      <div className="mt-2 text-xs text-slate-400 text-center max-w-xs">
        {score >= 80 && "Critical vulnerabilities detected requiring immediate remediation."}
        {score >= 60 && score < 80 && "High risk configuration flaws expand the system attack surface."}
        {score >= 40 && score < 60 && "Elevated security findings identified across system services."}
        {score >= 20 && score < 40 && "Moderate risk posture with minor policy warnings."}
        {score < 20 && "Low risk. Baseline configurations comply with standard security controls."}
      </div>
    </div>
  );
}
