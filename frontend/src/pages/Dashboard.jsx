import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ShieldAlert, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  HelpCircle, 
  ArrowRight,
  Server, 
  HardDrive, 
  Cpu, 
  Clock, 
  ExternalLink 
} from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { api } from '../services/api';
import RiskGauge from '../components/RiskGauge';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import FindingModal from '../components/FindingModal';

export default function Dashboard() {
  const navigate = useNavigate();
  const [latestAudit, setLatestAudit] = useState(null);
  const [systemInfo, setSystemInfo] = useState({});
  const [loading, setLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const auditsRes = await api.getAudits(1);
      if (auditsRes.data && auditsRes.data.length > 0) {
        const auditDetail = await api.getAudit(auditsRes.data[0].id);
        setLatestAudit(auditDetail.data);
        setSystemInfo(auditDetail.data.system_info || {});
      } else {
        // Fallback: trigger initial audit if empty
        const startRes = await api.startAudit();
        setLatestAudit(startRes.data);
        setSystemInfo(startRes.data.system_info || {});
      }
    } catch (err) {
      console.error("Dashboard data load error:", err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-10 h-10 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-3" />
          <p className="text-xs text-slate-400 font-mono">Loading Security Metrics...</p>
        </div>
      </div>
    );
  }

  if (!latestAudit) {
    return (
      <div className="p-8 text-center bg-[#111726] border border-slate-800 rounded-xl my-8">
        <p className="text-slate-400 mb-4">No audit scans recorded yet.</p>
        <button
          onClick={() => navigate('/audit')}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-lg text-xs"
        >
          Execute First Audit
        </button>
      </div>
    );
  }

  // Chart data for severity distribution
  const severityChartData = [
    { name: 'Critical', count: latestAudit.critical_count, color: '#ef4444' },
    { name: 'High', count: latestAudit.high_count, color: '#f97316' },
    { name: 'Medium', count: latestAudit.medium_count, color: '#eab308' },
    { name: 'Low', count: latestAudit.low_count, color: '#3b82f6' },
    { name: 'Info', count: latestAudit.info_count, color: '#64748b' },
  ];

  // Top critical / high findings
  const priorityFindings = (latestAudit.findings || [])
    .filter(f => f.status === 'FAIL' || f.status === 'WARNING')
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Top Banner / Assessment Overview */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gradient-to-r from-slate-900 to-[#111726] p-6 rounded-xl border border-slate-800/80 shadow-lg">
        <div>
          <span className="text-xs font-mono font-semibold uppercase tracking-wider text-blue-400">
            Defensive Security Assessment
          </span>
          <h1 className="text-2xl font-extrabold text-white mt-1">
            System Risk & Vulnerability Posture
          </h1>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            Continuous local audit evaluating account privileges, password policies, network exposure, SSH configuration, and filesystem permissions against CIS and defensive baselines.
          </p>
        </div>
        <button
          onClick={() => navigate('/audit')}
          className="self-start sm:self-center px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold transition shadow-lg shadow-blue-900/30 flex items-center gap-2"
        >
          <span>Run New Scan</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Main KPI Row: Risk Score + Check Counts + Severity Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Card 1: Risk Gauge */}
        <RiskGauge score={latestAudit.risk_score} level={latestAudit.risk_level} />

        {/* Card 2: Checks & Status Counts */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 flex flex-col justify-between shadow-md">
          <div>
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Audit Coverage</span>
            <div className="text-3xl font-extrabold text-white mt-2">
              {latestAudit.total_checks} <span className="text-xs font-normal text-slate-400">Security Checks</span>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 mt-4">
            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/30 flex items-center gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <div>
                <div className="text-lg font-bold text-emerald-400">{latestAudit.passed_checks}</div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Passed Checks</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-red-950/20 border border-red-900/30 flex items-center gap-3">
              <XCircle className="w-5 h-5 text-red-400" />
              <div>
                <div className="text-lg font-bold text-red-400">{latestAudit.failed_checks}</div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Failed Checks</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/30 flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
              <div>
                <div className="text-lg font-bold text-amber-400">{latestAudit.warning_count}</div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Warnings</div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 flex items-center gap-3">
              <HelpCircle className="w-5 h-5 text-slate-400" />
              <div>
                <div className="text-lg font-bold text-slate-300">{latestAudit.not_available_count}</div>
                <div className="text-[10px] text-slate-400 uppercase font-semibold">Unavailable</div>
              </div>
            </div>
          </div>
        </div>

        {/* Card 3: Severity Breakdown Chart */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md flex flex-col justify-between">
          <div>
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Severity Distribution</span>
            <div className="text-xs text-slate-500 mt-1">Weighted finding counts across categories</div>
          </div>

          <div className="h-44 w-full mt-2">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                <XAxis type="number" stroke="#475569" fontSize={11} />
                <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} width={50} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#090d16', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }} 
                  itemStyle={{ color: '#f8fafc' }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {severityChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Two Column Layout: System Card & Priority Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* System Profile Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-bold text-white">Target System Profile</h2>
            </div>
            <button 
              onClick={() => navigate('/system')}
              className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1"
            >
              Details <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/60 text-xs mt-3">
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Distribution</span>
              <span className="font-semibold text-slate-200">{systemInfo.distribution || 'Linux'}</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Kernel Version</span>
              <span className="font-mono text-slate-300 truncate max-w-[180px]">{systemInfo.kernel_version || 'N/A'}</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Architecture</span>
              <span className="font-mono text-slate-300">{systemInfo.architecture || 'x86_64'}</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Current User</span>
              <span className="font-mono text-slate-200">{systemInfo.current_user} (UID {systemInfo.current_uid})</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Privilege Level</span>
              <span className="font-medium text-emerald-400">{systemInfo.privilege_level || 'Standard User'}</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">Root Storage</span>
              <span className="font-mono text-slate-200">{systemInfo.disk_percent_used}% used ({systemInfo.disk_free_gb} GB free)</span>
            </div>
            <div className="py-2.5 flex justify-between">
              <span className="text-slate-400">System Uptime</span>
              <span className="text-slate-300">{systemInfo.uptime_human || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Priority Findings List */}
        <div className="lg:col-span-2 bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <h2 className="text-sm font-bold text-white">Priority Security Findings</h2>
              </div>
              <button 
                onClick={() => navigate('/findings')}
                className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1"
              >
                View All ({latestAudit.findings?.length || 0}) <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            <div className="space-y-3 mt-4">
              {priorityFindings.map((finding) => (
                <div
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className="p-3.5 rounded-lg bg-slate-900/60 hover:bg-slate-800/60 border border-slate-800 hover:border-slate-700 cursor-pointer transition flex items-start justify-between gap-4 group"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <StatusBadge status={finding.status} />
                      <span className="text-xs font-semibold text-slate-400">[{finding.category}]</span>
                      <h4 className="text-xs font-bold text-slate-200 group-hover:text-blue-400 transition">
                        {finding.title}
                      </h4>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-1">
                      {finding.description}
                    </p>
                  </div>
                  <ExternalLink className="w-4 h-4 text-slate-500 group-hover:text-slate-300 flex-shrink-0" />
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-500 flex justify-between">
            <span>Showing top {priorityFindings.length} actionable items</span>
            <span className="text-slate-400">Click any finding to inspect evidence & remediation commands</span>
          </div>
        </div>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <FindingModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
