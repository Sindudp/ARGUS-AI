from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import json
import os
import sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)
from tools.anomaly_detector import ARGUSAnomalyDetector

REPORT_PATH = os.path.join(BASE_DIR, "data", "latest_report.json")

app = FastAPI(
    title="ARGUS-AI",
    description="Autonomous Response and Guardian for Unified Security - AI-powered SOC platform",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = ARGUSAnomalyDetector()
detector.train()

alerts_db = []
alert_counter = 0


class LogEvent(BaseModel):
    timestamp: str
    source_ip: str
    dest_ip: str
    event_type: str
    status: Optional[str] = None
    count: Optional[int] = 1
    bytes_sent: Optional[int] = 0
    ports_scanned: Optional[int] = 0
    files_encrypted: Optional[int] = 0
    user: Optional[str] = None
    port: Optional[int] = None
    attack_type: Optional[str] = None
    description: Optional[str] = None


class LogBatch(BaseModel):
    logs: List[LogEvent]


def level_for(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


@app.get("/")
def root():
    return {
        "system": "ARGUS-AI",
        "status": "ONLINE",
        "version": "1.1.0",
        "description": "Autonomous multi-agent cybersecurity SOC platform",
        "agents": ["Triage Specialist", "Senior Investigator", "Incident Response Commander"],
        "ml_model": "Isolation Forest",
        "endpoints": ["/analyze", "/alerts", "/stats", "/report", "/simulate", "/health"],
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "ml_model": "trained",
        "timestamp": datetime.now().isoformat(),
        "total_alerts": len(alerts_db),
    }


@app.post("/analyze")
def analyze_logs(batch: LogBatch):
    global alert_counter
    if not batch.logs:
        raise HTTPException(status_code=400, detail="No logs provided")

    results = []
    for log in batch.logs:
        log_dict = log.model_dump()
        ml = detector.predict(log_dict)

        alert_counter += 1
        alert = {
            "alert_id": f"ARGUS-{alert_counter:04d}",
            "timestamp": log.timestamp,
            "source_ip": log.source_ip,
            "dest_ip": log.dest_ip,
            "event_type": log.event_type,
            "is_anomaly": bool(ml["is_anomaly"]),
            "severity_score": ml["severity_score"],
            "anomaly_score": ml["anomaly_score"],
            "status": level_for(ml["severity_score"]),
            "detected_at": datetime.now().isoformat(),
            "features": ml["features_analyzed"],
        }
        if ml["is_anomaly"]:
            alerts_db.append(alert)
        results.append(alert)

    return {
        "analyzed": len(results),
        "anomalies_found": sum(1 for r in results if r["is_anomaly"]),
        "results": results,
    }


@app.get("/alerts")
def get_alerts(severity: Optional[str] = None, limit: int = 50):
    filtered = alerts_db
    if severity:
        filtered = [a for a in alerts_db if a["status"] == severity.upper()]
    return {"total": len(filtered), "alerts": filtered[-limit:]}


@app.get("/stats")
def get_stats():
    if not alerts_db:
        return {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                "top_threat_ips": []}

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    ip_counts = {}
    for a in alerts_db:
        counts[a["status"]] += 1
        ip_counts[a["source_ip"]] = ip_counts.get(a["source_ip"], 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    return {
        "total_alerts": len(alerts_db),
        "critical": counts["CRITICAL"],
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "top_threat_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
    }


@app.delete("/alerts")
def clear_alerts():
    global alerts_db, alert_counter
    alerts_db = []
    alert_counter = 0
    return {"message": "All alerts cleared", "status": "success"}


@app.get("/report")
def get_report():
    """Latest AI investigation report written by agents/argus_pipeline.py"""
    if not os.path.exists(REPORT_PATH):
        return {"available": False,
                "message": "No report yet. Run: python agents/argus_pipeline.py"}
    with open(REPORT_PATH, encoding="utf-8") as f:
        report = json.load(f)
    report["available"] = True
    return report


@app.post("/simulate")
def simulate_attack():
    now = datetime.now().isoformat()
    sample = LogBatch(logs=[
        LogEvent(timestamp=now, source_ip="192.168.1.105", dest_ip="10.0.0.1",
                 event_type="login_attempt", status="failed", count=47, user="admin"),
        LogEvent(timestamp=now, source_ip="10.0.0.1", dest_ip="185.220.101.45",
                 event_type="data_transfer", bytes_sent=524288000, port=443),
        LogEvent(timestamp=now, source_ip="192.168.1.200", dest_ip="10.0.0.1",
                 event_type="port_scan", ports_scanned=1000),
        LogEvent(timestamp=now, source_ip="192.168.1.2", dest_ip="192.168.1.25",
                 event_type="lateral_movement", files_encrypted=15000),
    ])
    return analyze_logs(sample)
