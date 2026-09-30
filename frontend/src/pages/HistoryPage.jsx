import React, { useState, useEffect } from 'react';
import { History, Calendar, ShieldCheck, ArrowRight, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';

export default function HistoryPage() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadAudits();
  }, []);

  const loadAudits = async () => {
    try {
      setLoading(true);
      const res = await api.getAudits(50);
      setAudits(res.data);
    } catch (err) {
      console.error("Error loading audit history:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <History className="w-5 h-5 text-blue-400" />
            <h1 className="text-xl font-extrabold text-white">Historical Security Audits</h1>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Track security posture trajectories, risk score fluctuations, and historical assessment records across time.
          </p>
        </div>

        <button
          onClick={loadAudits}
          className="self-start sm:self-center px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh History</span>
        </button>
      </div>

      {/* History Table */}
      <div className="bg-[#111726] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 font-mono">
            <div className="w-6 h-6 border-2 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-2" />
            Loading audit timelines...
          </div>
        ) : audits.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No previous audits recorded in the database.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider">
                  <th className="py-3 px-4">Audit ID</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Target Host</th>
                  <th className="py-3 px-4">Mode</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Posture</th>
                  <th className="py-3 px-4">Checks Passed/Failed</th>
                  <th className="py-3 px-4">Critical / High</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {audits.map((a) => {
                  let scoreColor = 'text-emerald-400';
                  if (a.risk_score >= 80) scoreColor = 'text-red-400';
                  else if (a.risk_score >= 60) scoreColor = 'text-orange-400';
                  else if (a.risk_score >= 40) scoreColor = 'text-amber-400';
                  else if (a.risk_score >= 20) scoreColor = 'text-blue-400';

                  return (
                    <tr key={a.id} className="hover:bg-slate-800/50 transition">
                      <td className="py-3.5 px-4 font-bold text-white">
                        {a.id}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-sans">
                        {new Date(a.started_at).toLocaleString()}
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        {a.hostname}
                      </td>
                      <td className="py-3.5 px-4">
                        {a.is_demo ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                            DEMO
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            LIVE
                          </span>
                        )}
                      </td>
                      <td className={`py-3.5 px-4 font-extrabold text-sm ${scoreColor}`}>
                        {a.risk_score} / 100
                      </td>
                      <td className={`py-3.5 px-4 font-bold text-[11px] ${scoreColor}`}>
                        {a.risk_level}
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        <span className="text-emerald-400">{a.passed_checks} Pass</span> / <span className="text-red-400">{a.failed_checks} Fail</span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="text-red-400 font-bold">{a.critical_count}</span> Crit / <span className="text-orange-400 font-bold">{a.high_count}</span> High
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
