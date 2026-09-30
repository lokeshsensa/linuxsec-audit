import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  ShieldCheck, 
  LayoutDashboard, 
  PlayCircle, 
  Search, 
  Server, 
  Network, 
  Cpu, 
  History, 
  FileText, 
  BookOpen,
  Terminal
} from 'lucide-react';

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/audit', label: 'Run Audit', icon: PlayCircle },
  { to: '/findings', label: 'Findings', icon: Search },
  { to: '/system', label: 'System Info', icon: Server },
  { to: '/network', label: 'Network & Ports', icon: Network },
  { to: '/services', label: 'Services', icon: Cpu },
  { to: '/history', label: 'Audit History', icon: History },
  { to: '/reports', label: 'Export Reports', icon: FileText },
  { to: '/learn', label: 'Security Knowledge', icon: BookOpen },
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-[#0d121f] border-r border-slate-800/80 flex flex-col flex-shrink-0 min-h-screen">
      {/* Brand logo & title */}
      <div className="p-5 border-b border-slate-800/80 flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
          <ShieldCheck className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h1 className="font-extrabold text-sm tracking-wider text-white">
            LINUX<span className="text-blue-500">SEC</span>AUDIT
          </h1>
          <p className="text-[10px] uppercase font-mono tracking-widest text-slate-400">
            Defensive Auditor v1.0
          </p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="p-3 flex-1 space-y-1">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-semibold transition-all ${
                  isActive
                    ? 'bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent'
                }`
              }
            >
              <Icon className="w-4 h-4 flex-shrink-0" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
      </nav>

      {/* Defensive Safety Notice in Footer */}
      <div className="p-4 m-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5 text-emerald-400 font-bold mb-1">
          <Terminal className="w-3.5 h-3.5" />
          <span>SAFE DEFENSIVE MODE</span>
        </div>
        <p className="text-slate-400 leading-snug">
          Read-only audit inspection. Recommendation-only remediations.
        </p>
      </div>
    </aside>
  );
}
