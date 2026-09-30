import React, { useState, useEffect } from 'react';
import { Cpu, Search, CheckCircle2, XCircle, RefreshCw, AlertCircle } from 'lucide-react';
import { api } from '../services/api';

export default function ServicesPage() {
  const [services, setServices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [filterState, setFilterState] = useState('ALL');

  useEffect(() => {
    loadServices();
  }, []);

  const loadServices = async () => {
    try {
      setLoading(true);
      const res = await api.getServices();
      setServices(res.data);
    } catch (err) {
      console.error("Error loading services:", err);
    } finally {
      setLoading(false);
    }
  };

  const filteredServices = services.filter((s) => {
    const matchesSearch =
      s.name.toLowerCase().includes(search.toLowerCase()) ||
      (s.description && s.description.toLowerCase().includes(search.toLowerCase()));

    if (filterState === 'FAILED') return matchesSearch && s.is_failed;
    if (filterState === 'ACTIVE') return matchesSearch && !s.is_failed;
    return matchesSearch;
  });

  const failedCount = services.filter(s => s.is_failed).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Cpu className="w-5 h-5 text-blue-400" />
            <h1 className="text-xl font-extrabold text-white">System Services & Daemons</h1>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Inspecting active and failed systemd units. Verifying daemon health and auditing for unnecessary legacy services.
          </p>
        </div>

        <button
          onClick={loadServices}
          className="self-start sm:self-center px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Services</span>
        </button>
      </div>

      {/* Control bar */}
      <div className="bg-[#111726] border border-slate-800/80 p-4 rounded-xl flex flex-col md:flex-row gap-3 items-center justify-between shadow-md">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search service name or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-[#090d16] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <button
            onClick={() => setFilterState('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filterState === 'ALL'
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            All ({services.length})
          </button>
          <button
            onClick={() => setFilterState('ACTIVE')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filterState === 'ACTIVE'
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Running ({services.length - failedCount})
          </button>
          <button
            onClick={() => setFilterState('FAILED')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
              filterState === 'FAILED'
                ? 'bg-red-600 text-white'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Failed ({failedCount})
          </button>
        </div>
      </div>

      {/* Services Table */}
      <div className="bg-[#111726] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 font-mono">
            <div className="w-6 h-6 border-2 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-2" />
            Querying systemctl units...
          </div>
        ) : filteredServices.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No services matching query.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider">
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Unit Name</th>
                  <th className="py-3 px-4">Load</th>
                  <th className="py-3 px-4">Active</th>
                  <th className="py-3 px-4">Sub-State</th>
                  <th className="py-3 px-4">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {filteredServices.map((s, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/50 transition">
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {s.is_failed ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-950/80 text-red-400 border border-red-800/60">
                          <XCircle className="w-3 h-3" /> FAILED
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                          <CheckCircle2 className="w-3 h-3" /> RUNNING
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 font-bold text-white max-w-xs truncate">
                      {s.name}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400">{s.load}</td>
                    <td className="py-3.5 px-4 text-emerald-400 font-semibold">{s.active}</td>
                    <td className="py-3.5 px-4 text-slate-300">{s.sub}</td>
                    <td className="py-3.5 px-4 text-slate-400 font-sans max-w-md truncate">
                      {s.description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
