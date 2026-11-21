# tools/evaluate.py
# Purpose: measure how well the ML detector works on a HELD-OUT labeled test set.
# The test set uses a different random seed from the training data.

import os
import sys
import json
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

from tools.anomaly_detector import ARGUSAnomalyDetector


def build_test_set(seed=7, n_benign=300, n_each_attack=30):
    rng = np.random.default_rng(seed)
    events = []

    for _ in range(n_benign):
        kind = int(rng.integers(0, 3))
        if kind == 0:     # ordinary logins
            c = int(rng.integers(1, 5))
            status = "failed" if (c < 3 and rng.random() < 0.3) else "success"
            events.append(({"event_type": "login_attempt", "status": status, "count": c}, 0, "benign"))
        elif kind == 1:   # ordinary data transfers
            events.append(({"event_type": "data_transfer", "count": 1,
                            "bytes_sent": int(rng.integers(1_000, 10_000_000))}, 0, "benign"))
        else:             # ordinary web traffic
            events.append(({"event_type": "web_request", "count": 1,
                            "ports_scanned": int(rng.integers(0, 5))}, 0, "benign"))

    for _ in range(n_each_attack):
        c = int(rng.integers(20, 120))
        events.append(({"event_type": "login_attempt", "status": "failed", "count": c}, 1, "brute_force"))
        events.append(({"event_type": "data_transfer", "count": 1,
                        "bytes_sent": int(rng.integers(100_000_000, 1_000_000_000))}, 1, "exfiltration"))
        events.append(({"event_type": "port_scan", "count": 1,
                        "ports_scanned": int(rng.integers(300, 1000))}, 1, "port_scan"))
        events.append(({"event_type": "lateral_movement", "count": 1,
                        "files_encrypted": int(rng.integers(3000, 15000))}, 1, "ransomware"))
    return events


def rule_baseline(event):
    """A simple hand-written threshold rule, for comparison."""
    return int(event.get("count", 1) > 10
               or event.get("bytes_sent", 0) > 20_000_000
               or event.get("ports_scanned", 0) > 50
               or event.get("files_encrypted", 0) > 100)


def metrics(y_true, y_pred):
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3)}


if __name__ == "__main__":
    detector = ARGUSAnomalyDetector()
    detector.train()

    events = build_test_set()
    y_true = [label for _, label, _ in events]
    kinds = [kind for _, _, kind in events]

    ml_pred = [int(detector.predict(e)["is_anomaly"]) for e, _, _ in events]
    rule_pred = [rule_baseline(e) for e, _, _ in events]

    ml = metrics(y_true, ml_pred)
    rule = metrics(y_true, rule_pred)

    per_attack = {}
    for k in ("brute_force", "exfiltration", "port_scan", "ransomware"):
        idx = [i for i, kk in enumerate(kinds) if kk == k]
        per_attack[k] = round(sum(ml_pred[i] for i in idx) / len(idx), 3)

    print("\n" + "=" * 60)
    print("ARGUS-AI ML EVALUATION (held-out synthetic test set)")
    print("=" * 60)
    print(f"Test events: {len(events)}  (benign {y_true.count(0)}, attacks {y_true.count(1)})")
    print(f"Training outlier share (contamination): {detector.contamination}")
    print("\n{:<28}{:>10}{:>10}{:>10}".format("Method", "Precision", "Recall", "F1"))
    print("{:<28}{:>10}{:>10}{:>10}".format("Isolation Forest (ARGUS)", ml["precision"], ml["recall"], ml["f1"]))
    print("{:<28}{:>10}{:>10}{:>10}".format("Fixed-threshold rule", rule["precision"], rule["recall"], rule["f1"]))
    print("\nConfusion matrix, Isolation Forest:")
    print(f"  TP={ml['tp']}  FP={ml['fp']}  FN={ml['fn']}  TN={ml['tn']}")
    print("\nRecall per attack type, Isolation Forest:")
    for k, v in per_attack.items():
        print(f"  {k:<14}{v}")
    print("\nNOTE: results are on synthetic data, so they are indicative only.")

    out = {"isolation_forest": ml, "rule_baseline": rule,
           "recall_per_attack": per_attack, "n_events": len(events)}
    os.makedirs(os.path.join(ROOT, "data"), exist_ok=True)
    with open(os.path.join(ROOT, "data", "evaluation_results.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("Saved data/evaluation_results.json")
