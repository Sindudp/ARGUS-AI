import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import axios from 'axios';

const API = 'http://127.0.0.1:8000';

const COLORS = {
  CRITICAL: '#DC2626',
  HIGH: '#EA580C', 
  MEDIUM: '#D97706',
  LOW: '#16A34A'
};

function App() {
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);

  const fetchData = async () => {
    try {
      const [statsRes, alertsRes, healthRes] = await Promise.all([
        axios.get(`${API}/stats`),
        axios.get(`${API}/alerts`),
        axios.get(`${API}/health`)
      ]);
      setStats(statsRes.data);
      setAlerts(alertsRes.data.alerts.reverse());
      setHealth(healthRes.data);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('API Error:', err);
    }
  };

  const simulateAttack = async () => {
    setSimulating(true);
    try {
      await axios.post(`${API}/simulate`);
      await fetchData();
    } catch (err) {
      console.error('Simulate Error:', err);
    }
    setSimulating(false);
  };

  const clearAlerts = async () => {
    try {
      await axios.delete(`${API}/alerts`);
      await fetchData();
    } catch (err) {
      console.error('Clear Error:', err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const pieData = stats ? [
    { name: 'Critical', value: stats.critical, color: COLORS.CRITICAL },
    { name: 'High', value: stats.high, color: COLORS.HIGH },
    { name: 'Medium', value: stats.medium, color: COLORS.MEDIUM },
    { name: 'Low', value: stats.low, color: COLORS.LOW },
  ].filter(d => d.value > 0) : [];

  const barData = stats?.top_threat_ips?.map(ip => ({
    ip: ip.ip,
    alerts: ip.count
  })) || [];

  return (
    <div style={{
      backgroundColor: '#0a0f1e',
      minHeight: '100vh',
      color: '#e2e8f0',
      fontFamily: "'Courier New', monospace",
      padding: '20px'
    }}>

      {/* Header */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '24px',
        borderBottom: '1px solid #1e3a5f',
        paddingBottom: '16px'
      }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '24px', color: '#00d4ff', letterSpacing: '3px' }}>
            ⚡ ARGUS-AI
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#64748b' }}>
            Autonomous Response & Guardian for Unified Security
          </p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            backgroundColor: health?.status === 'healthy' ? '#052e16' : '#450a0a',
            border: `1px solid ${health?.status === 'healthy' ? '#16a34a' : '#dc2626'}`,
            borderRadius: '20px',
            padding: '6px 14px',
            fontSize: '12px'
          }}>
            <div style={{
              width: '8px', height: '8px', borderRadius: '50%',
              backgroundColor: health?.status === 'healthy' ? '#16a34a' : '#dc2626',
              animation: 'pulse 2s infinite'
            }}/>
            {health?.status === 'healthy' ? '🟢 SYSTEM ONLINE' : '🔴 SYSTEM OFFLINE'}
          </div>
          <p style={{ margin: '4px 0 0', fontSize: '11px', color: '#64748b' }}>
            Last updated: {lastUpdated || 'Loading...'}
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        {[
          { label: 'TOTAL ALERTS', value: stats?.total_alerts || 0, color: '#00d4ff', bg: '#0c1a2e' },
          { label: 'CRITICAL', value: stats?.critical || 0, color: '#dc2626', bg: '#1a0a0a' },
          { label: 'HIGH', value: stats?.high || 0, color: '#ea580c', bg: '#1a0f0a' },
          { label: 'MEDIUM', value: stats?.medium || 0, color: '#d97706', bg: '#1a150a' },
        ].map((card, i) => (
          <div key={i} style={{
            backgroundColor: card.bg,
            border: `1px solid ${card.color}33`,
            borderRadius: '8px',
            padding: '16px',
            textAlign: 'center'
          }}>
            <div style={{ fontSize: '36px', fontWeight: 'bold', color: card.color }}>
              {card.value}
            </div>
            <div style={{ fontSize: '11px', color: '#64748b', letterSpacing: '2px', marginTop: '4px' }}>
              {card.label}
            </div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '24px' }}>

        {/* Pie Chart */}
        <div style={{
          backgroundColor: '#0c1a2e',
          border: '1px solid #1e3a5f',
          borderRadius: '8px',
          padding: '16px'
        }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '13px', color: '#00d4ff', letterSpacing: '2px' }}>
            THREAT DISTRIBUTION
          </h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label={({name, value}) => `${name}: ${value}`}>
                  {pieData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b' }}>
              No alerts yet — click Simulate Attack
            </div>
          )}
        </div>

        {/* Bar Chart */}
        <div style={{
          backgroundColor: '#0c1a2e',
          border: '1px solid #1e3a5f',
          borderRadius: '8px',
          padding: '16px'
        }}>
          <h3 style={{ margin: '0 0 16px', fontSize: '13px', color: '#00d4ff', letterSpacing: '2px' }}>
            TOP THREAT IPs
          </h3>
          {barData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={barData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e3a5f" />
                <XAxis dataKey="ip" tick={{ fill: '#64748b', fontSize: 10 }} />
                <YAxis tick={{ fill: '#64748b', fontSize: 10 }} />
                <Tooltip contentStyle={{ backgroundColor: '#0c1a2e', border: '1px solid #1e3a5f' }} />
                <Bar dataKey="alerts" fill="#00d4ff" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b' }}>
              No threat IPs detected yet
            </div>
          )}
        </div>
      </div>

      {/* Action Buttons */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px' }}>
        <button onClick={simulateAttack} disabled={simulating} style={{
          backgroundColor: simulating ? '#1e3a5f' : '#dc2626',
          color: 'white',
          border: 'none',
          borderRadius: '6px',
          padding: '10px 20px',
          cursor: simulating ? 'not-allowed' : 'pointer',
          fontSize: '13px',
          fontFamily: 'monospace',
          letterSpacing: '1px'
        }}>
          {simulating ? '⏳ DETECTING...' : '🔴 SIMULATE ATTACK'}
        </button>
        <button onClick={fetchData} style={{
          backgroundColor: '#0c1a2e',
          color: '#00d4ff',
          border: '1px solid #1e3a5f',
          borderRadius: '6px',
          padding: '10px 20px',
          cursor: 'pointer',
          fontSize: '13px',
          fontFamily: 'monospace',
          letterSpacing: '1px'
        }}>
          🔄 REFRESH
        </button>
        <button onClick={clearAlerts} style={{
          backgroundColor: '#0c1a2e',
          color: '#64748b',
          border: '1px solid #1e3a5f',
          borderRadius: '6px',
          padding: '10px 20px',
          cursor: 'pointer',
          fontSize: '13px',
          fontFamily: 'monospace',
          letterSpacing: '1px'
        }}>
          🗑️ CLEAR ALERTS
        </button>
      </div>

      {/* Alerts Table */}
      <div style={{
        backgroundColor: '#0c1a2e',
        border: '1px solid #1e3a5f',
        borderRadius: '8px',
        padding: '16px'
      }}>
        <h3 style={{ margin: '0 0 16px', fontSize: '13px', color: '#00d4ff', letterSpacing: '2px' }}>
          LIVE ALERT FEED — {alerts.length} ALERTS
        </h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                {['ALERT ID', 'TIME', 'SOURCE IP', 'DEST IP', 'EVENT TYPE', 'SEVERITY', 'STATUS'].map(h => (
                  <th key={h} style={{ padding: '8px', textAlign: 'left', color: '#64748b', letterSpacing: '1px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '24px', textAlign: 'center', color: '#64748b' }}>
                    No alerts detected — click SIMULATE ATTACK to begin
                  </td>
                </tr>
              ) : (
                alerts.map((alert, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid #0f2744' }}>
                    <td style={{ padding: '8px', color: '#00d4ff' }}>{alert.alert_id}</td>
                    <td style={{ padding: '8px', color: '#64748b' }}>{new Date(alert.detected_at).toLocaleTimeString()}</td>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{alert.source_ip}</td>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{alert.dest_ip}</td>
                    <td style={{ padding: '8px', color: '#e2e8f0' }}>{alert.event_type}</td>
                    <td style={{ padding: '8px' }}>
                      <span style={{
                        color: 'white',
                        backgroundColor: COLORS[alert.status] || '#64748b',
                        padding: '2px 8px',
                        borderRadius: '12px',
                        fontSize: '11px'
                      }}>
                        {alert.severity_score}/100
                      </span>
                    </td>
                    <td style={{ padding: '8px' }}>
                      <span style={{ color: COLORS[alert.status] || '#64748b', fontWeight: 'bold' }}>
                        {alert.status}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <p style={{ textAlign: 'center', color: '#1e3a5f', fontSize: '11px', marginTop: '24px' }}>
        ARGUS-AI v1.0 — Autonomous Multi-Agent Cybersecurity SOC Platform — Auto-refresh every 5 seconds
      </p>
    </div>
  );
}

export default App;