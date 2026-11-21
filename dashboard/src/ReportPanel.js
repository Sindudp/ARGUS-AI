import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API = 'http://127.0.0.1:8000';

const box = {
  backgroundColor: '#0c1a2e',
  border: '1px solid #1e3a5f',
  borderRadius: '8px',
  padding: '16px',
  marginBottom: '16px',
};

const heading = {
  margin: '0 0 12px',
  fontSize: '13px',
  color: '#00d4ff',
  letterSpacing: '2px',
};

function TextBlock({ title, text }) {
  return (
    <div style={box}>
      <h3 style={heading}>{title}</h3>
      <div style={{
        whiteSpace: 'pre-wrap',
        fontSize: '12px',
        color: '#cbd5e1',
        lineHeight: 1.6,
        maxHeight: '320px',
        overflowY: 'auto',
      }}>
        {text || 'Not available'}
      </div>
    </div>
  );
}

export default function ReportPanel() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(false);

  const load = async () => {
    try {
      const res = await axios.get(`${API}/report`);
      setReport(res.data);
      setError(false);
    } catch (err) {
      setError(true);
    }
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div style={{ color: '#e2e8f0', fontFamily: "'Courier New', monospace" }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <h2 style={{ margin: 0, fontSize: '16px', color: '#00d4ff', letterSpacing: '3px' }}>
          AI INVESTIGATION REPORT
        </h2>
        <button onClick={load} style={{
          backgroundColor: '#0c1a2e', color: '#00d4ff', border: '1px solid #1e3a5f',
          borderRadius: '6px', padding: '8px 16px', cursor: 'pointer',
          fontFamily: 'monospace', fontSize: '12px',
        }}>
          LOAD LATEST REPORT
        </button>
      </div>

      {error && <div style={box}>Cannot reach the ARGUS API. Is uvicorn running?</div>}

      {report && !report.available && !error && (
        <div style={box}>{report.message}</div>
      )}

      {report && report.available && (
        <>
          <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '12px' }}>
            Generated: {report.generated_at} | Model: {report.model}
          </div>

          <div style={box}>
            <h3 style={heading}>ML DETECTION SUMMARY (Isolation Forest)</h3>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
                  {['GROUP', 'SOURCE IP', 'EVENT TYPE', 'EVENTS', 'ML FLAGGED', 'ML SEVERITY'].map((h) => (
                    <th key={h} style={{ padding: '8px', textAlign: 'left', color: '#64748b' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.ml_summary.map((g) => (
                  <tr key={g.group} style={{ borderBottom: '1px solid #0f2744' }}>
                    <td style={{ padding: '8px', color: '#00d4ff' }}>{g.group}</td>
                    <td style={{ padding: '8px' }}>{g.source_ip}</td>
                    <td style={{ padding: '8px' }}>{g.event_type}</td>
                    <td style={{ padding: '8px' }}>{g.event_count}</td>
                    <td style={{ padding: '8px' }}>{g.ml_anomalous_events}</td>
                    <td style={{ padding: '8px' }}>{g.ml_max_severity}/100</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <TextBlock title="TRIAGE AGENT" text={report.triage} />
          <TextBlock title="INVESTIGATION AGENT (CVE + MITRE tools)" text={report.investigation} />
          <TextBlock title="RESPONSE AGENT - PLAYBOOKS" text={report.playbooks} />
        </>
      )}
    </div>
  );
}
