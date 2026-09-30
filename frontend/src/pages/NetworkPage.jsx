import React, { useState, useEffect } from 'react';
import { Network, ShieldAlert, Globe, Lock, RefreshCw, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';

export default function NetworkPage() {
  const [ports, setPorts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadPorts();
  }, []);

  const loadPorts = async () => {
    try {
      setLoading(true);
      const res = await api.getNetworkPorts();
      setPorts(res.data);
    } catch (err) {
      console.error("Error loading network ports:", err);
    } finally {
      setLoading(false);
    }
  };

  const exposedPorts = ports.filter(p => !p.is_loopback);
  const loopbackPorts = ports.filter(p => p.is_loopback);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Network className="w-5 h-5 text-blue-400" />
            <h1 className="text-xl font-extrabold text-white">Listening Network Ports & Exposure</h1>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Inspecting local listening network sockets (ss/netstat). Distinguishing public/wildcard exposures from loopback-restricted internal daemons.
          </p>
        </div>

        <button
          onClick={loadPorts}
          className="self-start sm:self-center px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold flex items-center gap-1.5 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Sockets</span>
        </button>
      </div>

      {/* KPI Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        <div className="p-5 rounded-xl bg-[#111726] border border-slate-800 shadow-md">
          <div className="text-xs uppercase font-mono tracking-wider text-slate-400">Total Open Sockets</div>
          <div className="text-3xl font-extrabold text-white mt-1">{ports.length}</div>
          <div className="text-xs text-slate-500 mt-1">Active TCP/UDP listening daemons</div>
        </div>

        <div className="p-5 rounded-xl bg-[#111726] border border-red-900/40 bg-red-950/10 shadow-md">
          <div className="text-xs uppercase font-mono tracking-wider text-red-400 flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5" /> External Interfaces (0.0.0.0 / ::)
          </div>
          <div className="text-3xl font-extrabold text-red-400 mt-1">{exposedPorts.length}</div>
          <div className="text-xs text-slate-400 mt-1">Directly reachable over network if unfirewalled</div>
        </div>

        <div className="p-5 rounded-xl bg-[#111726] border border-emerald-900/40 bg-emerald-950/10 shadow-md">
          <div className="text-xs uppercase font-mono tracking-wider text-emerald-400 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5" /> Loopback Restricted (127.0.0.1)
          </div>
          <div className="text-3xl font-extrabold text-emerald-400 mt-1">{loopbackPorts.length}</div>
          <div className="text-xs text-slate-400 mt-1">Internal inter-process communication only</div>
        </div>
      </div>

      {/* Ports Table */}
      <div className="bg-[#111726] border border-slate-800/80 rounded-xl overflow-hidden shadow-lg">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-400 font-mono">
            <div className="w-6 h-6 border-2 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-2" />
            Querying network sockets...
          </div>
        ) : ports.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500">
            No active listening ports detected on system.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-900/60 text-slate-400 uppercase font-mono tracking-wider">
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4">Port</th>
                  <th className="py-3 px-4">Service</th>
                  <th className="py-3 px-4">Binding Address</th>
                  <th className="py-3 px-4">Exposure Level</th>
                  <th className="py-3 px-4">Service Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {ports.map((p, idx) => {
                  const isExposed = !p.is_loopback;
                  return (
                    <tr key={idx} className="hover:bg-slate-800/50 transition">
                      <td className="py-3.5 px-4 font-bold text-slate-300">
                        {p.protocol}
                      </td>
                      <td className="py-3.5 px-4 font-bold text-blue-400">
                        {p.port}
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-slate-200">
                        {p.service_name}
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        {p.address}:{p.port}
                      </td>
                      <td className="py-3.5 px-4">
                        {isExposed ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-950/80 text-red-400 border border-red-800/60">
                            <Globe className="w-3 h-3" /> Wildcard / External
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                            <Lock className="w-3 h-3" /> Loopback Only
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 font-sans text-xs">
                        {p.service_description}
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
