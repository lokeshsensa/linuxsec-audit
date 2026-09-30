import React, { useState, useEffect } from 'react';
import { Server, HardDrive, Cpu, Activity, Shield, Terminal, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

export default function SystemPage() {
  const [system, setSystem] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSystem();
  }, []);

  const loadSystem = async () => {
    try {
      setLoading(true);
      const res = await api.getSystem();
      setSystem(res.data);
    } catch (err) {
      console.error("System info error:", err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-blue-500/20 border-t-blue-500 rounded-full animate-spin mx-auto mb-2" />
          <p className="text-xs text-slate-400 font-mono">Querying system metrics...</p>
        </div>
      </div>
    );
  }

  if (!system) {
    return <div className="p-8 text-center text-slate-400">Failed to load system profile.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white">System Profile & Hardware Inventory</h1>
            <p className="text-xs text-slate-400 mt-1">
              Host hardware architecture, kernel version, storage accounting, and security privilege capabilities.
            </p>
          </div>
        </div>
      </div>

      {/* Grid of System Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {/* Operating System Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800 text-xs font-bold text-slate-300">
            <Server className="w-4 h-4 text-blue-400" />
            <span>OPERATING SYSTEM</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Distribution:</span>
              <span className="font-bold text-white">{system.distribution}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Kernel Version:</span>
              <span className="font-mono text-slate-300 truncate max-w-[170px]">{system.kernel_version}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Architecture:</span>
              <span className="font-mono text-slate-300">{system.architecture}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Hostname:</span>
              <span className="font-mono font-bold text-blue-400">{system.hostname}</span>
            </div>
          </div>
        </div>

        {/* User & Privilege Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800 text-xs font-bold text-slate-300">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>SECURITY IDENTITY</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Current User:</span>
              <span className="font-bold text-white">{system.current_user}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">User UID:</span>
              <span className="font-mono text-slate-300">{system.current_uid}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Privilege Status:</span>
              <span className="font-bold text-emerald-400">{system.privilege_level}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Package Manager:</span>
              <span className="font-mono text-slate-300 uppercase">{system.package_manager}</span>
            </div>
          </div>
        </div>

        {/* Storage Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800 text-xs font-bold text-slate-300">
            <HardDrive className="w-4 h-4 text-purple-400" />
            <span>STORAGE (ROOT FILESYSTEM)</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Total Capacity:</span>
              <span className="font-mono text-white">{system.disk_total_gb} GB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Used Space:</span>
              <span className="font-mono text-amber-400">{system.disk_used_gb} GB ({system.disk_percent_used}%)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Free Space:</span>
              <span className="font-mono text-emerald-400">{system.disk_free_gb} GB</span>
            </div>
            {/* Progress bar */}
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mt-1">
              <div
                className={`h-full ${system.disk_percent_used > 85 ? 'bg-red-500' : 'bg-blue-500'}`}
                style={{ width: `${Math.min(system.disk_percent_used, 100)}%` }}
              />
            </div>
          </div>
        </div>

        {/* Compute & Memory Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800 text-xs font-bold text-slate-300">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>COMPUTE & MEMORY</span>
          </div>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Logical CPU Cores:</span>
              <span className="font-mono text-white">{system.cpu_count}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">RAM Total:</span>
              <span className="font-mono text-slate-300">{system.memory_total_mb} MB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">RAM Available:</span>
              <span className="font-mono text-emerald-400">{system.memory_available_mb} MB</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">System Uptime:</span>
              <span className="font-mono text-slate-300">{system.uptime_human}</span>
            </div>
          </div>
        </div>

        {/* Runtime Environment Card */}
        <div className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md md:col-span-2">
          <div className="flex items-center gap-2 mb-3 pb-2 border-b border-slate-800 text-xs font-bold text-slate-300">
            <Terminal className="w-4 h-4 text-amber-400" />
            <span>AUDIT EXECUTION RUNTIME</span>
          </div>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-slate-400">Python Interpreter:</span>
                <span className="font-mono text-slate-300">{system.python_version}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Platform Subsystem:</span>
                <span className="font-mono text-slate-300">{system.os_name} {system.os_release}</span>
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between">
                <span className="text-slate-400">Audit Safety Guard:</span>
                <span className="font-bold text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Read-Only Defensive
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Destructive Actions:</span>
                <span className="font-mono text-slate-400">Strictly Prohibited</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
