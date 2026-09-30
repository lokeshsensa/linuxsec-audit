import axios from 'axios';

// When running on standard Vite port 5173, talk directly to FastAPI at port 8000
// to avoid Vite node-level proxy socket restrictions.
const getBaseUrl = () => {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname || 'localhost';
    if (window.location.port === '5173') {
      return `http://${host}:8000/api`;
    }
  }
  return '/api';
};

const API_BASE = getBaseUrl();

export const api = {
  getHealth: () => axios.get(`${API_BASE}/health`),
  getSystem: () => axios.get(`${API_BASE}/system`),
  getServices: () => axios.get(`${API_BASE}/services`),
  getNetworkPorts: () => axios.get(`${API_BASE}/network/ports`),
  getAudits: (limit = 20) => axios.get(`${API_BASE}/audits?limit=${limit}`),
  getAudit: (id) => axios.get(`${API_BASE}/audit/${id}`),
  getFindings: (params = {}) => axios.get(`${API_BASE}/findings`, { params }),
  startAudit: (demoMode = null) => axios.post(`${API_BASE}/audit/start`, { demo_mode: demoMode }),
  getReportJsonUrl: (auditId) => `${API_BASE}/reports/${auditId}/json`,
  getReportCsvUrl: (auditId) => `${API_BASE}/reports/${auditId}/csv`,
  getReportHtmlUrl: (auditId) => `${API_BASE}/reports/${auditId}/html`,
};
