# LinuxSecAudit 🛡️
### Production-Grade Defensive Linux Security Auditing & Risk Assessment Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-brightgreen.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4-38B2AC.svg)](https://tailwindcss.com/)

**LinuxSecAudit** is an authorized, non-destructive defensive security auditing engine and modern SOC dashboard designed to evaluate local Linux operating systems for common security misconfigurations, credential policy weaknesses, exposed network services, and privilege escalation vectors.

The platform calculates a transparent, normalized risk score (0–100), categorizes findings into standardized severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), and provides human-readable explanations alongside actionable remediation instructions.

---

## 📌 Table of Contents
1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [Architecture & System Design](#architecture--system-design)
4. [Defensive Safety Boundaries](#defensive-safety-boundaries)
5. [Audit Modules & Check Catalog](#audit-modules--check-catalog)
6. [Risk Scoring Methodology](#risk-scoring-methodology)
7. [Installation & Setup](#installation--setup)
8. [CLI Usage](#cli-usage)
9. [Web Dashboard & SOC Console](#web-dashboard--soc-console)
10. [REST API Documentation](#rest-api-documentation)
11. [Reports & Exports](#reports--exports)
12. [Demo Mode vs Live Mode](#demo-mode-vs-live-mode)
13. [Cybersecurity Concepts & Learning Reference](#cybersecurity-concepts--learning-reference)
14. [Testing & Verification](#testing--verification)
15. [Limitations & Disclaimer](#limitations--disclaimer)

---

## 1. Project Overview

Managing Linux server security requires proactive configuration analysis against recognized industry standards (such as the CIS Linux Benchmarks and NIST guidelines). **LinuxSecAudit** provides systems administrators, DevSecOps engineers, and cybersecurity students with a reliable local assessment tool that inspects:

* **Privileged Accounts & Identity**: UID 0 backdoors, daemon accounts with interactive shells, and excessive sudo members.
* **Password Aging & Complexity**: `/etc/login.defs` policies and PAM password strength enforcement (`pam_pwquality`).
* **SSH Hardening**: PermitRootLogin, empty password allowance, authentication mechanisms, and session restrictions.
* **Filesystem & Permission Integrity**: Strict permission audits for sensitive files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`), world-writable scripts in `/opt` and `/etc`, and unusual SUID/SGID binaries.
* **Network & Daemon Exposure**: Listening TCP/UDP sockets, identifying unencrypted legacy daemons (Telnet, FTP) and exposed database sockets bound to `0.0.0.0`.
* **Host Packet Filtering**: UFW, Firewalld, nftables, and iptables status.
* **Kernel Security Parameters**: ASLR mode, privileged core dump prevention, dmesg restriction, and IP routing flags.
* **Patch Management**: Simulated non-destructive security update checks via APT, DNF, or Pacman.

---

## 2. Key Features

* **Zero-Crash Resilient Engine**: Audit modules execute within isolated safety envelopes; failure in one subsystem (e.g. absent firewall command) logs as `NOT_AVAILABLE` and never terminates the entire audit.
* **Transparent Scoring Engine**: Normalized 0–100 risk score based on documented severity weights and status penalties.
* **Full-Featured Dark SOC Dashboard**: Modern cybersecurity console built with React 18, Vite, Lucide icons, and Recharts.
* **Detailed Remediation Guidance**: Every finding provides human-readable explanations, observed system evidence, copyable fix commands, and CIS benchmark references.
* **Multi-Format Reporting**: Export reports to standalone Executive HTML (with embedded styles and gauges), machine-readable JSON, and tabular CSV.
* **Historical Audit Tracking**: Persisted SQLite database tracking risk score trends and remediation progression over time.
* **Dual Operation Modes**: Live Linux host inspection or instant simulated Demo Mode for demonstration on macOS/Windows.
* **Dual Interface**: Operate via CLI (`python -m app.cli audit`) or interactive Web UI.

---

## 3. Architecture & System Design

```
linuxsec-audit/
│
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application entrypoint & lifespan
│   │   ├── config.py            # App settings (Pydantic BaseSettings)
│   │   ├── cli.py               # CLI runner with format flags
│   │   ├── api/                 # REST API endpoints
│   │   │   ├── routes_audit.py
│   │   │   ├── routes_findings.py
│   │   │   ├── routes_system.py
│   │   │   └── routes_reports.py
│   │   ├── auditors/            # Individual defensive check modules
│   │   │   ├── base.py          # BaseAuditor abstract class
│   │   │   ├── system.py        # Host & hardware collector
│   │   │   ├── users.py         # UID 0, shells, and sudo groups
│   │   │   ├── passwords.py     # login.defs and PAM policies
│   │   │   ├── ssh.py           # sshd_config parser & checks
│   │   │   ├── permissions.py   # Sensitive files, SUID/SGID, world-writable
│   │   │   ├── services.py      # systemd units & legacy protocols
│   │   │   ├── network.py       # ss/netstat socket inspector
│   │   │   ├── firewall.py      # UFW, firewalld, nftables, iptables
│   │   │   ├── updates.py       # APT/DNF/Pacman simulation checks
│   │   │   ├── cron.py          # Scheduled tasks permissions
│   │   │   └── kernel.py        # /proc/sys sysctl security flags
│   │   ├── core/
│   │   │   ├── audit_engine.py  # Orchestrator running auditors & saving runs
│   │   │   ├── risk_engine.py   # 0-100 severity-weighted risk scoring
│   │   │   ├── command_runner.py# Safe subprocess execution with allowlist
│   │   │   └── logger.py        # Structured logging (secrets excluded)
│   │   ├── models/              # Pydantic schemas (Audit, Finding, Enums)
│   │   ├── database/            # SQLAlchemy models & SQLite engine
│   │   ├── reports/             # HTML, JSON, and CSV report builders
│   │   └── demo/                # Realistic simulated enterprise server data
│   ├── tests/                   # Pytest test suite
│   ├── requirements.txt
│   └── pytest.ini
│
├── frontend/                    # React 18 + Vite + Tailwind CSS + Recharts
│   ├── src/
│   │   ├── components/          # RiskGauge, Badges, Modals, Progress
│   │   ├── pages/               # Dashboard, Audit, Findings, System, Network...
│   │   ├── services/            # Axios API client
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── scripts/
│   ├── install.sh               # Complete automated installer
│   ├── start.sh                 # Launcher for backend + frontend
│   └── run_audit.sh             # Quick CLI runner
│
├── reports/                     # Generated audit reports
├── logs/                        # Application audit logs
├── .gitignore
├── LICENSE
└── README.md
```

---

## 4. Defensive Safety Boundaries

LinuxSecAudit strictly follows defensive security best practices:

* ✅ **Non-Destructive**: Reads configuration files and queries process/network tables.
* ✅ **Recommendation-Only**: Does NOT alter system files, modify users, or change firewall rules automatically.
* ✅ **Zero Secret Disclosure**: Never reads, displays, or logs password hashes from `/etc/shadow` or private keys.
* ✅ **Command Allowlist**: Subprocess calls are validated against a strict allowlist without `shell=True`.
* ✅ **Timeouts**: Every external utility call (`systemctl`, `ss`, `apt-get`) is protected by strict execution timeouts.

---

## 5. Audit Modules & Check Catalog

| Category | Checks Performed | Severity Threshold |
| :--- | :--- | :--- |
| **System** | Running as root vs unprivileged user; root disk partition utilization. | FAIL if disk >= 90%; WARNING if disk >= 80%. |
| **Users** | Non-root accounts with numeric UID 0; daemon accounts with interactive shells; administrative group sprawl. | HIGH if extra UID 0 detected; MEDIUM if daemons have interactive shells. |
| **Passwords** | Minimum password length (`PASS_MIN_LEN`), maximum lifetime (`PASS_MAX_DAYS`), minimum change delay, PAM complexity (`pam_pwquality`). | MEDIUM if min length < 12; WARNING if expiration > 90 days. |
| **SSH** | `PermitEmptyPasswords`, `PermitRootLogin`, `PasswordAuthentication`, `X11Forwarding`, `MaxAuthTries`. | CRITICAL if empty passwords permitted; HIGH if root login permitted. |
| **Permissions** | File metadata on `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`; world-writable scripts in `/opt` and `/etc`; SUID/SGID binaries. | CRITICAL if `/etc/shadow` world-readable; HIGH if sensitive files world-writable. |
| **Services** | Failed systemd units; legacy unencrypted daemons (telnet, rsh, rlogin, vsftpd); high-value databases. | HIGH if unencrypted remote shell running; MEDIUM if services failed. |
| **Network** | Listening TCP/UDP sockets; public wildcard bindings (`0.0.0.0`) vs loopback (`127.0.0.1`); database exposure. | HIGH if MySQL/Redis/Mongo exposed on `0.0.0.0`. |
| **Firewall** | Active status of UFW, firewalld, nftables, or iptables. | MEDIUM if all firewall tooling is missing or inactive. |
| **Updates** | Simulated package updates via APT (`apt-get -s upgrade`) or DNF/Pacman. | HIGH if >5 security updates pending; MEDIUM if 1-5 security updates pending. |
| **Cron** | Permissions on `/etc/crontab` and `/etc/cron.*`; checking for world-writable scheduled tasks. | CRITICAL if cron job is world-writable; HIGH if owned by non-root. |
| **Kernel** | ASLR mode (`randomize_va_space`), SUID core dumps (`suid_dumpable`), dmesg restriction, IPv4 forwarding. | CRITICAL if ASLR is 0; HIGH if core dumps enabled for SUID. |

---

## 6. Risk Scoring Methodology

LinuxSecAudit rejects arbitrary scoring in favor of a documented, reproducible algorithm:

### Severity Weights
* **CRITICAL**: 10 penalty points
* **HIGH**: 7 penalty points
* **MEDIUM**: 4 penalty points
* **LOW**: 2 penalty points
* **INFO**: 0 penalty points

### Status Multipliers
* **FAIL**: `1.0` multiplier
* **WARNING**: `0.6` multiplier
* **PASS** / **NOT_AVAILABLE**: `0.0` multiplier

### Normalization Formula
$$\text{Raw Penalty} = \sum (\text{Severity Weight} \times \text{Status Multiplier})$$
$$\text{Risk Score} = \min\left(100, \text{round}\left(\frac{\text{Raw Penalty}}{85.0} \times 100\right)\right)$$

### Posture Classification
* `0 – 19`: **LOW RISK** (Baseline configurations comply with security controls)
* `20 – 39`: **MODERATE RISK** (Minor policy deviations or warnings identified)
* `40 – 59`: **ELEVATED RISK** (Actionable configuration flaws require remediation)
* `60 – 79`: **HIGH RISK** (Severe misconfigurations expand host attack surface)
* `80 – 100`: **CRITICAL RISK** (Critical vulnerabilities require immediate remediation)

---

## 7. Installation & Setup

### Prerequisites
* Python 3.11 or newer
* Node.js 18+ and npm (for frontend development)
* Linux (for live audits) or macOS/Windows (using Demo Mode)

### Automated Setup
```bash
# Clone the repository
git clone https://github.com/your-username/linuxsec-audit.git
cd linuxsec-audit

# Run the automated installer
./scripts/install.sh
```

### Manual Setup
```bash
# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Initialize database
python -c "from app.database.database import init_db; init_db()"

# Frontend setup
cd ../frontend
npm install
npm run build
```

---

## 8. CLI Usage

The command-line interface shares the exact same underlying `AuditEngine` as the REST API:

```bash
# Activate virtual environment
source backend/venv/bin/activate
cd backend

# Run audit in demo mode with console summary
python -m app.cli audit --demo

# Run live local Linux audit
python -m app.cli audit

# Export audit to standalone HTML report
python -m app.cli audit --demo --html -o ../reports/audit_report.html

# Export audit to machine-readable JSON
python -m app.cli audit --demo --json -o ../reports/audit_report.json

# Export audit to spreadsheet CSV
python -m app.cli audit --demo --csv -o ../reports/audit_report.csv

# Display verbose output including all passed checks
python -m app.cli audit --verbose

# Query system hardware & identity specifications
python -m app.cli info
```

---

## 9. Web Dashboard & SOC Console

Start both backend and frontend servers with one command:
```bash
./scripts/start.sh
```

* **Dashboard Web UI**: `http://localhost:5173`
* **FastAPI Backend**: `http://127.0.0.1:8000`
* **Swagger API Documentation**: `http://127.0.0.1:8000/docs`

### Dashboard Views
1. **Dashboard**: Executive summary, circular risk gauge, severity distribution bar chart, system overview, and top actionable findings.
2. **Run Audit**: Interactive audit runner with real-time stage progress animation across all 11 security check phases.
3. **Findings Catalog**: Search and filter by severity, category, or status with click-to-view modal inspection.
4. **System Profile**: Hardware inventory, kernel version, memory, storage utilization, and effective privilege identity.
5. **Network Exposure**: Listening TCP/UDP sockets table distinguishing wildcard (`0.0.0.0`) from loopback (`127.0.0.1`).
6. **Services**: Systemd daemon monitor showing running and failed service units.
7. **Audit History**: Historical audit tracking over time with risk score progression.
8. **Export Reports**: Live preview and download links for HTML, JSON, and CSV reports.
9. **Knowledge Base**: Built-in cybersecurity learning guide explaining technical terms.

---

## 10. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status and active operating mode. |
| `GET` | `/api/system` | Comprehensive target system specifications. |
| `POST` | `/api/audit/start` | Trigger a new security audit run (`demo_mode` optional). |
| `GET` | `/api/audits` | List historical audit summaries. |
| `GET` | `/api/audit/{id}` | Retrieve complete audit details and findings by ID. |
| `GET` | `/api/findings` | Query findings with category, severity, status, and search filters. |
| `GET` | `/api/services` | Query systemd service unit states. |
| `GET` | `/api/network/ports` | Query active listening TCP/UDP sockets. |
| `GET` | `/api/reports/{id}/html` | Render standalone executive HTML audit report. |
| `GET` | `/api/reports/{id}/json` | Download structured audit report in JSON format. |
| `GET` | `/api/reports/{id}/csv` | Download findings in tabular CSV format. |

---

## 11. Reports & Exports

Reports are written to the `reports/` directory:

1. **HTML Report**: Standalone, CSS-inlined report with SOC theme, executive risk gauge, and formatted technical evidence blocks. Perfect for stakeholder presentation.
2. **JSON Report**: Normalized schema with audit metadata, system hardware details, and finding objects suitable for ingestion into Splunk, Elastic, or Jira.
3. **CSV Export**: Standard spreadsheet export with Finding ID, Category, Severity, Status, Title, Evidence, and Remediation columns.

---

## 12. Demo Mode vs Live Mode

* **Live Mode (`DEMO_MODE=false`)**:
  When executed on a live Linux system, LinuxSecAudit directly queries `/etc/passwd`, `/etc/shadow`, `/etc/login.defs`, `/etc/ssh/sshd_config`, `systemctl`, `ss`, and `/proc/sys` kernel parameters.
* **Demo Mode (`DEMO_MODE=true`)**:
  When executed on macOS, Windows, or restricted container environments, the engine automatically simulates a realistic Ubuntu 24.04 LTS enterprise server with realistic vulnerabilities (unrestricted SSH root login, world-writable backup script, exposed MySQL port, pending security updates). The UI clearly displays the `DEMO MODE` badge.

---

## 13. Cybersecurity Concepts & Learning Reference

| Concept | Explanation | Defensive Audit Method |
| :--- | :--- | :--- |
| **UID 0** | The Linux kernel recognizes superuser privileges strictly by numeric UID == 0, not the username string. | Inspect `/etc/passwd` for any secondary account with UID 0 other than `root`. |
| **SUID / SGID** | Bit allowing an executable to run with file owner privileges (often root) instead of caller privileges. | Scan binary paths using `stat.S_ISUID` and alert on non-standard custom executables. |
| **World-Writable** | Permissions allowing any local user to modify a file (`S_IWOTH`). | Audit `/etc`, `/opt`, and `/usr/local` for regular files with the `o+w` bit set. |
| **PAM Quality** | Pluggable Authentication Modules enforcing password entropy and minimum length. | Inspect `/etc/pam.d/*` and `/etc/security/pwquality.conf` for minimum length and credit settings. |
| **ASLR** | Address Space Layout Randomization randomizes stack, heap, and library offsets in RAM. | Inspect `/proc/sys/kernel/randomize_va_space` (value `2` is required for full randomization). |
| **0.0.0.0 Exposure** | Binding a service to wildcard `0.0.0.0` exposes it to external network interfaces. | Check `ss -tuln` for database and administration daemons listening on non-loopback addresses. |

---

## 14. Testing & Verification

Automated unit and integration tests are implemented using `pytest`:

```bash
cd backend
venv/bin/pytest -v
```

Test coverage includes:
* Risk scoring algorithm calculation and boundary conditions (all pass, all critical, mixed findings).
* Safe auditor execution guaranteeing zero crashes on missing files or permissions.
* System metadata collection and parsing.
* FastAPI REST API endpoint responses (`/api/health`, `/api/system`, `/api/audit/start`, `/api/findings`).
* HTML, JSON, and CSV report serialization.

---

## 15. Limitations & Disclaimer

* **Defensive Configuration Assessment**: LinuxSecAudit is a defensive security posture and configuration auditing tool, not a dynamic penetration testing exploit framework.
* **Non-Exhaustive Vulnerability Scanning**: It audits system configuration parameters against security best practices; it does not perform memory corruption exploitation, web application fuzzing, or network packet injection.
* **Privilege Scope**: Certain deep filesystem audits (e.g. reading `/etc/shadow` metadata or inspecting private root-owned directories) require appropriate administrative permissions. When executed without elevated permissions, checks gracefully record `NOT_AVAILABLE` with explanatory notes.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
