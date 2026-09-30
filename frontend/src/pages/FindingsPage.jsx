import React, { useState, useEffect } from 'react';
import { Search, Filter, ShieldAlert, ArrowUpDown, ExternalLink, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import FindingModal from '../components/FindingModal';

const CATEGORIES = [
  'All',
  'System',
  'Users',
  'Passwords',
  'SSH',
  'Permissions',
  'Services',
  'Network',
  'Firewall',
  'Updates',
  'Cron',
  'Kernel'
];

const SEVERITIES = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const STATUSES = ['All', 'FAIL', 'WARNING', 'PASS', 'NOT_AVAILABLE'];

export default function FindingsPage() {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('All');
  const [selectedSeverity, setSelectedSeverity] = useState('All');
  const [selectedStatus, setSelectedStatus] = useState('All');
  const [activeFinding, setActiveFinding] = useState(null);

  useEffect(() => {
    fetchFindings();
  }, [selectedCategory, selectedSeverity, selectedStatus, search]);

  const fetchFindings = async () => {
    try {
      setLoading(true);
      const params = {};
      if (selectedCategory !== 'All') params.category = selectedCategory;
      if (selectedSeverity !== 'All') params.severity = selectedSeverity;
      if (selectedStatus !== 'All') params.status = selectedStatus;
      if (search.trim()) params.search = search.trim();

      const res = await api.getFindings(params);
      setFindings(res.data);
    } catch (err) {
      console.error("Error fetching findings:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#111726] border border-slate-800/80 p-5 rounded-xl shadow-lg">
        <div>
          <h1 className="text-xl font-extrabold text-white">Security Findings Catalog</h1>
          <p className="text-xs text-slate-400 mt-1">
            Search, filter, and review technical evidence and remediation advisories for all identified misconfigurations.
          </p>
        </div>

        <button
          onClick={fetchFindings}
          className="self-start sm:self-center px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111726] border border-slate-800/80 p-4 rounded-xl space-y-4 shadow-md">
        <div className="flex flex-col md:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search findings by title, description, or evidence..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#090d16] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Category Filter */}
          <div className="w-full md:w-48">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full bg-[#090d16] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>
                  Category: {cat}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <div className="w-full md:w-40">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-[#090d16] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {SEVERITIES.map((sev) => (
                <option key={sev} value={sev}>
                  Severity: {sev}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div className="w-full md:w-40">
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="w-full bg-[#090d16] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
            >
              {STATUSES.map((stat) => (
                <option key={stat} value={stat}>
                  Status: {stat}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Results Count */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/60">
          <span>Found <strong className="text-white">{findings.length}</strong> findings</span>
          <span>Click any finding row to view technical evidence & remediation guidance</span>
        </div>
      </div>

      {/* Findings Data Table */}
      <div className="bg-[#111726] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 font-mono">
            <div className="w-6 h-6 border-2 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-2" />
            Filtering findings...
          </div>
        ) : findings.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No security findings matching the selected filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Finding Title</th>
                  <th className="py-3 px-4">Evidence</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {findings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setActiveFinding(f)}
                    className="hover:bg-slate-800/50 cursor-pointer transition group"
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap font-semibold text-slate-300">
                      {f.category}
                    </td>
                    <td className="py-3.5 px-4 font-semibold text-slate-200 group-hover:text-blue-400 transition max-w-sm truncate">
                      {f.title}
                    </td>
                    <td className="py-3.5 px-4 font-mono text-[11px] text-amber-300/80 max-w-xs truncate">
                      {f.evidence || '—'}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <ExternalLink className="w-3.5 h-3.5 text-slate-500 group-hover:text-white inline" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {activeFinding && (
        <FindingModal finding={activeFinding} onClose={() => setActiveFinding(null)} />
      )}
    </div>
  );
}
