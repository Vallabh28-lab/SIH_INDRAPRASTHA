import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000/api';

export const apiClient = {
  async getMetrics() {
    const response = await axios.get(`${API_BASE_URL}/metrics`);
    return response.data;
  },

  async getIncidents() {
    const response = await axios.get(`${API_BASE_URL}/incidents`);
    return response.data;
  },

  async sendFlow(flowData) {
    const response = await axios.post(`${API_BASE_URL}/traffic`, flowData);
    return response.data;
  }
};

/**
 * Fetch real-time traffic events, top-level metric counters, and trend data
 */
export const fetchDashboardData = async (limit = 100) => {
  try {
    const response = await axios.get(`http://localhost:8000/api/traffic?limit=${limit}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch dashboard data:', error);
    throw error;
  }
};

/**
 * Fetch SHA-256 forensic audit trail records
 */
export const fetchAuditLogs = async (limit = 100) => {
  try {
    const response = await axios.get(`http://localhost:8000/api/audit?limit=${limit}`);
    return response.data;
  } catch (error) {
    console.error('Failed to fetch audit logs:', error);
    throw error;
  }
};

/**
 * Verify cryptographic hash-chain integrity of audit records
 */
export const verifyAuditIntegrity = async () => {
  try {
    const response = await axios.get('http://localhost:8000/api/audit/verify');
    return response.data;
  } catch (error) {
    console.error('Failed to verify audit integrity:', error);
    throw error;
  }
};

/**
 * Trigger simulated traffic event (Normal, SYN_Flood, Port_Scan, UDP_Flood)
 */
export const simulateTraffic = async (attackType) => {
  try {
    const response = await axios.post(`http://localhost:8000/api/traffic/simulate?attack_type=${attackType}`);
    return response.data;
  } catch (error) {
    console.error(`Failed to simulate ${attackType}:`, error);
    throw error;
  }
};

export default apiClient;
