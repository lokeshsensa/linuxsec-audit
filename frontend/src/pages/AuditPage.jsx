import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Play, CheckCircle2, ShieldAlert, ArrowRight, RefreshCw, Terminal, Eye, AlertOctagon } from 'lucide-react';
import { api } from '../services/api';
import AuditProgressBar, { AUDIT_STAGES } from '../components/AuditProgressBar';
import RiskGauge from '../components/RiskGauge';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export default function AuditPage() {
  const navigate = useNavigate();
  const [isRunning, setIsRunning] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [auditResult, setAuditResult] = useState(null);
  const [useDemo, setUseDemo] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  const handleStartAudit = async () => {
    setIsRunning(true);
    setCurrentStep(0);
    setAuditResult(null);
    setErrorMessage(null);

    try {
      // Initiate audit call
      const auditPromise = api.startAudit(useDemo);

      // Step through stages with nice visual pacing so user sees checks completing
      for (let i = 0; i < AUDIT_STAGES.length - 1; i++) {
        setCurrentStep(i);
        await sleep(220);
      }

      // Wait for backend execution to complete
      const res = await auditPromise;
      setCurrentStep(AUDIT_STAGES.length);
      await sleep(200);
      setAuditResult(res.data);
    } catch (err) {
      console.error("Audit run error:", err);
      const msg = err.response?.data?.detail || err.message || "Failed to execute audit. Check server connectivity.";
      setErrorMessage(`Audit execution encountered an issue: ${msg}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <h1 className="text-xl font-extrabold text-white">Execute Defensive Security Audit</h1>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Initiate automated non-destructive security inspection across local system accounts, PAM policies, SSH configuration, file permissions, listening network services, and kernel parameters.
        </p>

        {/* Configuration Bar */}
        <div className="mt-5 p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="text-xs font-semibold text-slate-300">Audit Mode:</span>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
              <input
                type="radio"
                name="auditMode"
                checked={useDemo}
                onChange={() => setUseDemo(true)}
                className="text-blue-600 focus:ring-blue-500"
              />
              <span className="font-semibold text-amber-400">Demo Mode (Simulated Lab Data)</span>
            </label>
            <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer ml-2">
              <input
                type="radio"
                name="auditMode"
                checked={!useDemo}
                onChange={() => setUseDemo(false)}
                className="text-blue-600 focus:ring-blue-500"
              />
              <span className="font-semibold text-emerald-400">Live Local System Audit</span>
            </label>
          </div>

          <button
            onClick={handleStartAudit}
            disabled={isRunning}
            className={`px-5 py-2.5 rounded-lg text-xs font-bold flex items-center gap-2 text-white shadow-lg transition ${
              isRunning
                ? 'bg-slate-700 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-500 shadow-blue-900/40 active:scale-95'
            }`}
          >
            {isRunning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Auditing In Progress...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Start Security Audit</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Error Message Card */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/80 text-red-200 flex items-start gap-3 shadow-lg">
          <AlertOctagon className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1 text-xs">
            <div className="font-bold text-red-400 text-sm mb-1">Audit Failed</div>
            <p>{errorMessage}</p>
            <div className="mt-3 flex gap-2">
              <button
                onClick={() => { setUseDemo(true); handleStartAudit(); }}
                className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs transition"
              >
                Run in Demo Mode Instead
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Progress Animation Bar */}
      {(isRunning || auditResult) && (
        <AuditProgressBar currentStep={currentStep} isRunning={isRunning} />
      )}

      {/* Post-Audit Result Card */}
      {auditResult && (
        <div className="bg-[#111726] border border-slate-800 rounded-xl p-6 shadow-xl animate-in fade-in duration-300">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <CheckCircle2 className="w-6 h-6 text-emerald-400" />
              <div>
                <h2 className="text-base font-bold text-white">Security Assessment Completed</h2>
                <p className="text-xs text-slate-400">
                  Audit ID: <span className="font-mono text-slate-300">{auditResult.id}</span> | Host: <span className="font-mono text-slate-300">{auditResult.hostname}</span>
                </p>
              </div>
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => navigate('/findings')}
                className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center gap-1.5 transition"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>View Findings ({auditResult.findings?.length || 0})</span>
              </button>
              <button
                onClick={() => navigate('/reports')}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold transition"
              >
                <span>Export Report</span>
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-6">
            <RiskGauge score={auditResult.risk_score} level={auditResult.risk_level} />

            <div className="space-y-3">
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Status Metrics</span>
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center text-xs">
                <span className="text-slate-400">Total Checks Evaluated</span>
                <span className="font-bold text-white font-mono">{auditResult.total_checks}</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center text-xs">
                <span className="text-emerald-400 font-semibold">Passed Checks</span>
                <span className="font-bold text-emerald-400 font-mono">{auditResult.passed_checks}</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center text-xs">
                <span className="text-red-400 font-semibold">Failed Checks</span>
                <span className="font-bold text-red-400 font-mono">{auditResult.failed_checks}</span>
              </div>
              <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800 flex justify-between items-center text-xs">
                <span className="text-amber-400 font-semibold">Security Warnings</span>
                <span className="font-bold text-amber-400 font-mono">{auditResult.warning_count}</span>
              </div>
            </div>

            <div className="space-y-3">
              <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Severity Breakdown</span>
              <div className="p-3 bg-red-950/20 rounded-lg border border-red-900/30 flex justify-between items-center text-xs">
                <span className="text-red-400 font-semibold">Critical Vulnerabilities</span>
                <span className="font-bold text-red-400 font-mono">{auditResult.critical_count}</span>
              </div>
              <div className="p-3 bg-orange-950/20 rounded-lg border border-orange-900/30 flex justify-between items-center text-xs">
                <span className="text-orange-400 font-semibold">High Severity Findings</span>
                <span className="font-bold text-orange-400 font-mono">{auditResult.high_count}</span>
              </div>
              <div className="p-3 bg-amber-950/20 rounded-lg border border-amber-900/30 flex justify-between items-center text-xs">
                <span className="text-amber-400 font-semibold">Medium Severity Findings</span>
                <span className="font-bold text-amber-400 font-mono">{auditResult.medium_count}</span>
              </div>
              <div className="p-3 bg-blue-950/20 rounded-lg border border-blue-900/30 flex justify-between items-center text-xs">
                <span className="text-blue-400 font-semibold">Low & Info Findings</span>
                <span className="font-bold text-blue-400 font-mono">{auditResult.low_count + auditResult.info_count}</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
