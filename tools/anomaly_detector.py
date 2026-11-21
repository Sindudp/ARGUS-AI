# tools/anomaly_detector.py
# Purpose: Isolation Forest anomaly detector for ARGUS-AI.
# It trains on UNLABELED synthetic traffic that is mostly normal and contains a
# few rare outliers (like real logs), then scores every log event from 0 to 100.

import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["login_attempts", "failed_logins", "bytes_transferred",
            "ports_scanned", "files_encrypted"]


def _num(value):
    """Turn None or missing values into 0."""
    return 0 if value is None else value


class ARGUSAnomalyDetector:
    def __init__(self, seed=42, n_normal=2000, n_outliers=80):
        self.seed = seed
        self.n_normal = n_normal
        self.n_outliers = n_outliers
        # contamination = the share of outliers we know we put in the training data
        self.contamination = round(n_outliers / (n_normal + n_outliers), 3)
        self.model = IsolationForest(
            n_estimators=300,
            contamination=self.contamination,
            random_state=seed,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.scale = 0.1

    def generate_training_data(self):
        """Mostly normal traffic plus a few rare outliers (each extreme in ONE feature)."""
        rng = np.random.default_rng(self.seed)
        n = self.n_normal
        has_transfer = rng.random(n) < 0.5
        normal = pd.DataFrame({
            "login_attempts": rng.integers(1, 5, n),
            "failed_logins": rng.integers(0, 3, n),
            "bytes_transferred": np.where(
                has_transfer, rng.integers(1_000, 10_000_000, n), 0),
            "ports_scanned": rng.integers(0, 5, n),
            "files_encrypted": np.zeros(n, dtype=int),
        })

        m = self.n_outliers
        outliers = normal.iloc[:m].copy()
        outliers[:] = 0
        outliers["login_attempts"] = 1
        for i in range(m):
            kind = i % 4
            if kind == 0:      # many failed logins
                c = int(rng.integers(5, 150))
                outliers.loc[i, ["login_attempts", "failed_logins"]] = [c, c]
            elif kind == 1:    # huge data transfer
                outliers.loc[i, "bytes_transferred"] = int(rng.integers(20_000_000, 1_000_000_000))
            elif kind == 2:    # large port scan
                outliers.loc[i, "ports_scanned"] = int(rng.integers(5, 1500))
            else:              # mass file encryption
                outliers.loc[i, "files_encrypted"] = int(rng.integers(100, 20_000))

        return pd.concat([normal, outliers], ignore_index=True)[FEATURES]

    def train(self):
        print("ARGUS ML Engine: training Isolation Forest...")
        frame = self.generate_training_data()
        scaled = self.scaler.fit_transform(frame)
        self.model.fit(scaled)
        decisions = self.model.decision_function(scaled)
        # the most unusual training point defines severity 100
        self.scale = max(abs(float(np.min(decisions))), 0.01)
        self.is_trained = True
        print("ARGUS ML Engine: training complete")
        return True

    def extract_features(self, log_event):
        count = _num(log_event.get("count", 1))
        failed = count if log_event.get("status") == "failed" else 0
        return {
            "login_attempts": count,
            "failed_logins": failed,
            "bytes_transferred": _num(log_event.get("bytes_sent", 0)),
            "ports_scanned": _num(log_event.get("ports_scanned", 0)),
            "files_encrypted": _num(log_event.get("files_encrypted", 0)),
        }

    def predict(self, log_event):
        if not self.is_trained:
            self.train()
        features = self.extract_features(log_event)
        frame = pd.DataFrame([features])[FEATURES]
        scaled = self.scaler.transform(frame)

        label = self.model.predict(scaled)[0]            # -1 anomaly, 1 normal
        raw = float(self.model.score_samples(scaled)[0])
        decision = float(self.model.decision_function(scaled)[0])

        severity = 0 if decision >= 0 else int(min(100, round(-decision / self.scale * 100)))
        return {
            "is_anomaly": bool(label == -1),
            "severity_score": severity,
            "anomaly_score": round(raw, 4),
            "features_analyzed": features,
        }

    def analyze_logs(self, logs):
        print("\nARGUS ML Engine: analyzing logs...")
        results = []
        for i, log in enumerate(logs):
            result = self.predict(log)
            result["log_index"] = i
            result["event_type"] = log.get("event_type", "unknown")
            result["source_ip"] = log.get("source_ip", "unknown")
            result["timestamp"] = log.get("timestamp", "unknown")
            status = "ANOMALY" if result["is_anomaly"] else "normal"
            print(f"  Event {i+1} [{result['event_type']}]: {status} | severity {result['severity_score']}/100")
            results.append(result)
        return results


if __name__ == "__main__":
    detector = ARGUSAnomalyDetector()
    detector.train()
    with open("data/sample_logs.json", encoding="utf-8") as f:
        sample = json.load(f)
    detector.analyze_logs(sample)
