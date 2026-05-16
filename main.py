from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from tools.anomaly_detector import ARGUSAnomalyDetector

# Initialize FastAPI app
app = FastAPI(
    title="ARGUS-AI",
    description="Autonomous Response and Guardian for Unified Security — AI-Powered SOC Platform",
    version="1.0.0"
)

# Allow frontend to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize ML detector
detector = ARGUSAnomalyDetector()
detector.train()

# In-memory storage for alerts
alerts_db = []
alert_counter = 0

# ─────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────
class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    dest_ip: str
    event_type: str
    status: Optional[str] = None
    count: Optional[int] = 1
    bytes_sent: Optional[int] = 0
    ports_scanned: Optional[int] = 0
    user: Optional[str] = None
    port: Optional[int] = None

class LogBatch(BaseModel):
    logs: List[LogEvent]

# ─────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────

@app.get("/")
def root():
    return {
        "system": "ARGUS-AI",
        "status": "🟢 ONLINE",
        "version": "1.0.0",
        "description": "Autonomous Multi-Agent Cybersecurity SOC Platform",
        "agents": ["Triage Specialist", "Senior Investigator", "Incident Response Commander"],
        "ml_model": "Isolation Forest",
        "endpoints": ["/analyze", "/alerts", "/stats", "/health"]
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "ml_model": "trained",
        "timestamp": datetime.now().isoformat(),
        "total_alerts": len(alerts_db)
    }

@app.post("/analyze")
def analyze_logs(batch: LogBatch):
    """Analyze a batch of log events using ML detection"""
    global alert_counter

    if not batch.logs:
        raise HTTPException(status_code=400, detail="No logs provided")

    results = []

    for log in batch.logs:
        log_dict = log.dict()

        # Run ML detection
        ml_result = detector.predict(log_dict)

        # Create alert
        alert_counter += 1
        alert = {
            "alert_id": f"ARGUS-{alert_counter:04d}",
            "timestamp": log.timestamp,
            "source_ip": log.source_ip,
            "dest_ip": log.dest_ip,
            "event_type": log.event_type,
            "is_anomaly": bool(ml_result['is_anomaly']),
            "severity_score": ml_result['severity_score'],
            "anomaly_score": ml_result['anomaly_score'],
            "status": "CRITICAL" if ml_result['severity_score'] >= 70 else
                      "HIGH" if ml_result['severity_score'] >= 50 else
                      "MEDIUM" if ml_result['severity_score'] >= 30 else "LOW",
            "detected_at": datetime.now().isoformat(),
            "features": ml_result['features_analyzed']
        }

        # Store alert
        if ml_result['is_anomaly']:
            alerts_db.append(alert)

        results.append(alert)

    return {
        "analyzed": len(results),
        "anomalies_found": sum(1 for r in results if r['is_anomaly']),
        "results": results
    }

@app.get("/alerts")
def get_alerts(severity: Optional[str] = None, limit: int = 50):
    """Get all stored alerts with optional severity filter"""
    filtered = alerts_db

    if severity:
        filtered = [a for a in alerts_db if a['status'] == severity.upper()]

    return {
        "total": len(filtered),
        "alerts": filtered[-limit:]  # Return last N alerts
    }

@app.get("/stats")
def get_stats():
    """Get ARGUS detection statistics"""
    if not alerts_db:
        return {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "top_threat_ips": []
        }

    # Count by severity
    critical = sum(1 for a in alerts_db if a['status'] == 'CRITICAL')
    high = sum(1 for a in alerts_db if a['status'] == 'HIGH')
    medium = sum(1 for a in alerts_db if a['status'] == 'MEDIUM')
    low = sum(1 for a in alerts_db if a['status'] == 'LOW')

    # Top threat IPs
    ip_counts = {}
    for alert in alerts_db:
        ip = alert['source_ip']
        ip_counts[ip] = ip_counts.get(ip, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_alerts": len(alerts_db),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "top_threat_ips": [{"ip": ip, "count": count} for ip, count in top_ips]
    }

@app.delete("/alerts")
def clear_alerts():
    """Clear all alerts"""
    global alerts_db, alert_counter
    alerts_db = []
    alert_counter = 0
    return {"message": "All alerts cleared", "status": "success"}

# Simulate attack for demo
@app.post("/simulate")
def simulate_attack():
    """Simulate a real attack for demo purposes"""
    sample_logs = LogBatch(logs=[
        LogEvent(
            timestamp=datetime.now().isoformat(),
            source_ip="192.168.1.105",
            dest_ip="10.0.0.1",
            event_type="login_attempt",
            status="failed",
            count=47,
            user="admin"
        ),
        LogEvent(
            timestamp=datetime.now().isoformat(),
            source_ip="10.0.0.1",
            dest_ip="185.220.101.45",
            event_type="data_transfer",
            bytes_sent=524288000,
            port=443
        ),
        LogEvent(
            timestamp=datetime.now().isoformat(),
            source_ip="192.168.1.200",
            dest_ip="10.0.0.1",
            event_type="port_scan",
            ports_scanned=1000
        )
    ])
    return analyze_logs(sample_logs) 
