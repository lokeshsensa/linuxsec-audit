import React, { useState } from 'react';
import { BookOpen, ShieldAlert, Key, Terminal, Lock, Cpu, Globe, Search } from 'lucide-react';

const SECURITY_CONCEPTS = [
  {
    term: "UID 0 (Superuser Privilege)",
    icon: ShieldAlert,
    color: "text-red-400 bg-red-950/30 border-red-800/40",
    definition: "In Unix and Linux systems, the kernel identifies superuser privileges purely by numeric UID == 0, regardless of the username.",
    whyItMatters: "Any secondary user assigned UID 0 (e.g. 'toor') possesses full root privileges, bypassing normal sudo auditing and password rotation policies.",
    defensiveAuditCheck: "Inspect /etc/passwd and pwd database for any account with numeric UID 0 other than 'root'."
  },
  {
    term: "SUID & SGID Permission Bits",
    icon: Key,
    color: "text-purple-400 bg-purple-950/30 border-purple-800/40",
    definition: "Set User ID (SUID) and Set Group ID (SGID) are special POSIX permission bits that execute a binary with the permissions of the file owner (typically root) rather than the executing user.",
    whyItMatters: "Standard binaries like /usr/bin/passwd require SUID to write to /etc/shadow. However, custom or vulnerable SUID binaries (or binaries with command injection flaws) allow unprivileged users to achieve instant root privilege escalation.",
    defensiveAuditCheck: "Scan standard binary paths (/usr/bin, /opt) using stat.S_ISUID and cross-reference against a known standard baseline."
  },
  {
    term: "World-Writable Files & Sticky Bits",
    icon: Lock,
    color: "text-orange-400 bg-orange-950/30 border-orange-800/40",
    definition: "A file or directory that any local user on the system has permission to modify (POSIX permission bit S_IWOTH / 002).",
    whyItMatters: "If a system configuration file, cron script, or shared binary is world-writable, any local low-privilege attacker can tamper with its contents or append malicious commands.",
    defensiveAuditCheck: "Evaluate stat.S_IWOTH on regular files in sensitive directories (/etc, /opt, /usr/local) and ensure world-writable shared directories have the sticky bit (stat.S_ISVTX) set."
  },
  {
    term: "PAM (Pluggable Authentication Modules)",
    icon: Terminal,
    color: "text-blue-400 bg-blue-950/30 border-blue-800/40",
    definition: "The Linux subsystem providing modular authentication, account restriction, and password management (pam_pwquality, pam_unix, pam_faillock).",
    whyItMatters: "Without PAM password complexity enforcement (e.g. pam_pwquality.so), users can pick simple dictionary words, leaving the host vulnerable to offline and online password cracking.",
    defensiveAuditCheck: "Verify /etc/pam.d/ and /etc/login.defs for minimum password length (PASS_MIN_LEN >= 12), rotation periods, and entropy modules."
  },
  {
    term: "ASLR (Address Space Layout Randomization)",
    icon: Cpu,
    color: "text-cyan-400 bg-cyan-950/30 border-cyan-800/40",
    definition: "A kernel security defense that randomizes memory layout locations of process memory (stack, VDSO, libraries, heap) upon execution.",
    whyItMatters: "ASLR prevents attackers from reliably exploiting buffer overflows or constructing Return-Oriented Programming (ROP) exploit chains by making target memory addresses unpredictable.",
    defensiveAuditCheck: "Inspect /proc/sys/kernel/randomize_va_space. Value 2 represents full randomization; value 0 indicates ASLR is disabled."
  },
  {
    term: "Wildcard Port Binding (0.0.0.0 vs 127.0.0.1)",
    icon: Globe,
    color: "text-amber-400 bg-amber-950/30 border-amber-800/40",
    definition: "Binding a network daemon to IP address 0.0.0.0 or [::] makes the socket listen on all network interfaces, including public/external network cards.",
    whyItMatters: "Databases (MySQL, Redis, MongoDB) and internal administration services bound to 0.0.0.0 without host firewall filtering expose authentication endpoints to the wider network.",
    defensiveAuditCheck: "Inspect ss / netstat output to identify database and management ports listening on 0.0.0.0 instead of 127.0.0.1."
  }
];

export default function LearnPage() {
  const [searchTerm, setSearchTerm] = useState('');

  const filtered = SECURITY_CONCEPTS.filter(c =>
    c.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.definition.toLowerCase().includes(searchTerm.toLowerCase()) ||
    c.whyItMatters.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-[#111726] border border-slate-800/80 p-6 rounded-xl shadow-lg">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-400">
            <BookOpen className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white">Linux Defensive Cybersecurity Knowledge Base</h1>
            <p className="text-xs text-slate-400 mt-1">
              Core concepts, architectural security principles, and defensive auditing rationale implemented in LinuxSecAudit.
            </p>
          </div>
        </div>

        {/* Search */}
        <div className="mt-4 relative max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search concepts (e.g. SUID, PAM, ASLR, UID 0)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#090d16] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Concept Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {filtered.map((item, idx) => {
          const Icon = item.icon;
          return (
            <div
              key={idx}
              className="bg-[#111726] border border-slate-800/80 rounded-xl p-5 shadow-md flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center gap-2.5 mb-3">
                  <div className={`p-2 rounded-lg border ${item.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <h3 className="font-bold text-sm text-white">{item.term}</h3>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="font-semibold text-slate-400 uppercase tracking-wider text-[10px]">Definition:</span>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">{item.definition}</p>
                  </div>

                  <div>
                    <span className="font-semibold text-amber-400 uppercase tracking-wider text-[10px]">Why It Matters in Security:</span>
                    <p className="text-slate-400 mt-0.5 leading-relaxed">{item.whyItMatters}</p>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 bg-slate-900/40 -mx-5 -mb-5 p-4 rounded-b-xl">
                <span className="font-mono text-[10px] uppercase font-bold text-emerald-400">Audit Implementation:</span>
                <p className="text-slate-400 font-mono text-[11px] mt-0.5">{item.defensiveAuditCheck}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
