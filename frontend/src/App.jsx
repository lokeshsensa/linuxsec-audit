import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';

// Pages
import Dashboard from './pages/Dashboard';
import AuditPage from './pages/AuditPage';
import FindingsPage from './pages/FindingsPage';
import SystemPage from './pages/SystemPage';
import NetworkPage from './pages/NetworkPage';
import ServicesPage from './pages/ServicesPage';
import HistoryPage from './pages/HistoryPage';
import ReportsPage from './pages/ReportsPage';
import LearnPage from './pages/LearnPage';

import { api } from './services/api';

export default function App() {
  const [health, setHealth] = useState({ is_demo: true });
  const [latestAudit, setLatestAudit] = useState(null);

  useEffect(() => {
    checkHealthAndAudits();
  }, []);

  const checkHealthAndAudits = async () => {
    try {
      const hRes = await api.getHealth();
      setHealth(hRes.data);

      const aRes = await api.getAudits(1);
      if (aRes.data && aRes.data.length > 0) {
        setLatestAudit(aRes.data[0]);
      }
    } catch (err) {
      console.warn("Backend not reachable or still booting:", err);
    }
  };

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-[#080c14] text-slate-100 font-sans">
        {/* Sidebar Navigation */}
        <Sidebar />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <Navbar
            isDemo={latestAudit ? latestAudit.is_demo : health.demo_mode}
            lastAuditTime={latestAudit?.started_at}
            hostname={latestAudit?.hostname || 'security-lab'}
          />

          <main className="flex-1 overflow-y-auto p-6 md:p-8">
            <div className="max-w-7xl mx-auto">
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/findings" element={<FindingsPage />} />
                <Route path="/system" element={<SystemPage />} />
                <Route path="/network" element={<NetworkPage />} />
                <Route path="/services" element={<ServicesPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/reports" element={<ReportsPage />} />
                <Route path="/learn" element={<LearnPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </div>
          </main>
        </div>
      </div>
    </BrowserRouter>
  );
}
