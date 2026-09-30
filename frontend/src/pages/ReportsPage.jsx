import React, { useState, useEffect } from 'react';
import { FileText, Download, ExternalLink, Code, Table, Eye, RefreshCw } from 'lucide-react';
import { api } from '../services/api';

export default function ReportsPage() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedAuditId, setSelectedAuditId] = useState('');

  useEffect(() => {
    loadAudits();
  }, []);

  const loadAudits = async () => {
    try {
      setLoading(true);
      const res = await api.getAudits(20);
      setAudits(res.data);
      if (res.data.length > 0) {
        setSelectedAuditId(res.data[0].id);
      }
    } catch (err) {
      console.error("Error loading audits for reports:", err);
    } finally {
      setLoading(false);
    }
  };

  const selectedAudit = audits.find(a => a.id === selectedAuditId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-400">
            <FileText className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white">Security Assessment Reports & Exports</h1>
            <p className="text-xs text-slate-400 mt-1">
              Export formal audit reports in standalone HTML format for executive presentation, CSV for spreadsheet analysis, or JSON for SIEM ingestion.
            </p>
          </div>
        </div>
      </div>

      {/* Audit Selector & Export Action Cards */}
      <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <label className="text-xs font-semibold text-slate-300">
            Select Assessment Run:
          </label>
          <select
            value={selectedAuditId}
            onChange={(e) => setSelectedAuditId(e.target.value)}
            className="bg-[#090d16] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-blue-500"
          >
            {audits.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id} — {a.hostname} ({new Date(a.started_at).toLocaleString()}) — Score: {a.risk_score}/100
              </option>
            ))}
          </select>
        </div>

        {selectedAudit && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-3 border-t border-slate-800">
            {/* HTML Report Card */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-blue-500/40 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400">
                    <FileText className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase bg-blue-950/60 text-blue-400 px-2 py-0.5 rounded border border-blue-800/50">
                    EXECUTIVE
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white">Standalone HTML Report</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Complete self-contained HTML assessment document with SOC styling, executive risk score, and technical remediation blocks.
                </p>
              </div>

              <div className="flex gap-2 mt-4 pt-3 border-t border-slate-800/60">
                <a
                  href={api.getReportHtmlUrl(selectedAudit.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex-1 py-2 px-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold flex items-center justify-center gap-1.5 transition"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Open Report</span>
                </a>
              </div>
            </div>

            {/* JSON Export Card */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-emerald-500/40 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="p-2 rounded-lg bg-emerald-600/20 text-emerald-400">
                    <Code className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase bg-emerald-950/60 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800/50">
                    SIEM / API
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white">Machine-Readable JSON</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Structured JSON payload containing all normalized findings, risk score coefficients, and hardware metadata.
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/60">
                <a
                  href={api.getReportJsonUrl(selectedAudit.id)}
                  download={`linuxsec_audit_${selectedAudit.id}.json`}
                  className="w-full py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center justify-center gap-1.5 transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download JSON</span>
                </a>
              </div>
            </div>

            {/* CSV Export Card */}
            <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-purple-500/40 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="p-2 rounded-lg bg-purple-600/20 text-purple-400">
                    <Table className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase bg-purple-950/60 text-purple-400 px-2 py-0.5 rounded border border-purple-800/50">
                    SPREADSHEET
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white">Tabular CSV Export</h3>
                <p className="text-xs text-slate-400 mt-1">
                  CSV format containing finding IDs, categories, severities, evidence, and remediation steps ready for Excel or Jira import.
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/60">
                <a
                  href={api.getReportCsvUrl(selectedAudit.id)}
                  download={`linuxsec_audit_${selectedAudit.id}.csv`}
                  className="w-full py-2 px-3 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold flex items-center justify-center gap-1.5 transition"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download CSV</span>
                </a>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Embedded Live HTML Preview */}
      {selectedAudit && (
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
          <div className="p-4 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Live HTML Report Preview ({selectedAudit.id})
            </h3>
            <a
              href={api.getReportHtmlUrl(selectedAudit.id)}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-semibold"
            >
              Open Full Screen <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
          <iframe
            src={api.getReportHtmlUrl(selectedAudit.id)}
            title="Audit Report Preview"
            className="w-full h-[600px] border-none bg-slate-950"
          />
        </div>
      )}
    </div>
  );
}
