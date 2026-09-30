import React, { useState } from 'react';
import { X, Copy, Check, Terminal, ShieldAlert, BookOpen } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import StatusBadge from './StatusBadge';

export default function FindingModal({ finding, onClose }) {
  const [copied, setCopied] = useState(false);

  if (!finding) return null;

  const handleCopy = () => {
    if (finding.recommendation) {
      navigator.clipboard.writeText(finding.recommendation);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="bg-[#111726] border border-slate-800 rounded-xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between bg-slate-900/60">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
              <span className="text-xs font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {finding.category}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                ID: {finding.id}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white">
              {finding.title}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content body */}
        <div className="p-6 overflow-y-auto space-y-5 text-sm">
          {/* Description */}
          <div>
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-400 mb-2 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-blue-400" />
              Description & Security Impact
            </h3>
            <p className="text-slate-300 leading-relaxed bg-slate-900/40 p-3.5 rounded-lg border border-slate-800/80">
              {finding.description}
            </p>
          </div>

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-400 mb-2 flex items-center gap-1.5">
                <Terminal className="w-4 h-4 text-amber-400" />
                Observed System Evidence
              </h3>
              <div className="bg-[#090d16] border border-slate-800 rounded-lg p-3 font-mono text-xs text-amber-200/90 overflow-x-auto selection:bg-amber-900/50">
                {finding.evidence}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs uppercase tracking-wider font-bold text-emerald-400 flex items-center gap-1.5">
                <Check className="w-4 h-4" />
                Remediation & Recommendation
              </h3>
              <button
                onClick={handleCopy}
                className="text-xs flex items-center gap-1 text-slate-400 hover:text-emerald-400 transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <div className="bg-emerald-950/20 border border-emerald-900/40 p-3.5 rounded-lg text-emerald-200/90 leading-relaxed font-mono text-xs">
              {finding.recommendation}
            </div>
          </div>

          {/* Technical Context */}
          {finding.technical_details && (
            <div>
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-400 mb-2 flex items-center gap-1.5">
                <BookOpen className="w-4 h-4 text-purple-400" />
                Technical Context & Benchmark Standards
              </h3>
              <p className="text-slate-400 text-xs bg-slate-900/30 p-3 rounded-lg border border-slate-800/60 font-mono">
                {finding.technical_details}
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/50 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
