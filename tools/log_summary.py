# tools/log_summary.py
# Purpose: helpers for the ARGUS pipeline (testable without CrewAI)
#  - summarize_logs: score every raw event with the ML model, then group them.
#    The simulator's attack_type label is used ONLY for grouping and is hidden
#    from the agents, so they must work out the attack from the evidence.
#  - task_text: read the text output of a finished CrewAI task
#  - save_report: write the final report as JSON

import json
import os
from collections import defaultdict
from datetime import datetime


def summarize_logs(logs, detector, hide_labels=True):
    groups = defaultdict(list)
    for log in logs:
        key = (log.get("attack_type", "UNKNOWN"), log["source_ip"])
        groups[key].append((log, detector.predict(log)))

    summary = []
    for number, ((attack_type, source_ip), items) in enumerate(groups.items(), start=1):
        first = items[0][0]
        entry = {
            "group": f"G{number}",
            "source_ip": source_ip,
            "dest_ip": first["dest_ip"],
            "event_type": first["event_type"],
            "event_count": len(items),
            "first_seen": first["timestamp"],
            "last_seen": items[-1][0]["timestamp"],
            "ml_anomalous_events": sum(1 for _, r in items if r["is_anomaly"]),
            "ml_max_severity": max(r["severity_score"] for _, r in items),
        }
        if not hide_labels:
            entry["attack_type"] = attack_type
        for field in ("status", "user", "description"):
            if field in first:
                entry[field] = first[field]
        for field in ("count", "bytes_sent", "ports_scanned", "files_encrypted"):
            values = [lg[field] for lg, _ in items if field in lg]
            if values:
                entry["max_" + field] = max(values)
        summary.append(entry)
    return summary


def task_text(task):
    output = getattr(task, "output", None)
    if output is None:
        return ""
    raw = getattr(output, "raw", None)
    return raw if raw else str(output)


def save_report(path, summary, triage, investigation, playbooks, model_name):
    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "model": model_name,
        "ml_summary": summary,
        "triage": triage,
        "investigation": investigation,
        "playbooks": playbooks,
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return report
