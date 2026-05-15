import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import os

class ARGUSAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,  # 10% of data expected to be anomalous
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def generate_training_data(self, n_samples=1000):
        """Generate synthetic normal network traffic for training"""
        np.random.seed(42)
        
        normal_data = {
            # Normal login attempts: 1-5 per session
            'login_attempts': np.random.randint(1, 5, n_samples),
            # Normal data transfer: 1KB to 10MB (in bytes)
            'bytes_transferred': np.random.randint(1000, 10000000, n_samples),
            # Normal ports scanned: 0-5
            'ports_scanned': np.random.randint(0, 5, n_samples),
            # Normal session duration: 1-60 minutes
            'session_duration': np.random.randint(1, 60, n_samples),
            # Normal failed logins: 0-3
            'failed_logins': np.random.randint(0, 3, n_samples),
        }
        return pd.DataFrame(normal_data)

    def train(self):
        """Train Isolation Forest on normal traffic"""
        print("🔧 ARGUS ML Engine: Training Isolation Forest...")
        training_data = self.generate_training_data()
        scaled_data = self.scaler.fit_transform(training_data)
        self.model.fit(scaled_data)
        self.is_trained = True
        print("✅ ARGUS ML Engine: Training complete!")
        return True

    def extract_features(self, log_event):
        """Extract numerical features from a log event"""
        features = {
            'login_attempts': log_event.get('count', 1),
            'bytes_transferred': log_event.get('bytes_sent', 0),
            'ports_scanned': log_event.get('ports_scanned', 0),
            'session_duration': 5,  # default
            'failed_logins': log_event.get('count', 0) if log_event.get('status') == 'failed' else 0,
        }
        return features

    def predict(self, log_event):
        """Predict if a log event is anomalous"""
        if not self.is_trained:
            self.train()

        features = self.extract_features(log_event)
        feature_df = pd.DataFrame([features])
        scaled_features = self.scaler.transform(feature_df)
        
        # -1 = anomaly, 1 = normal
        prediction = self.model.predict(scaled_features)[0]
        # Anomaly score: more negative = more anomalous
        anomaly_score = self.model.score_samples(scaled_features)[0]
        
        # Convert to 0-100 severity score
        # score_samples returns negative values, more negative = more anomalous
        severity = min(100, max(0, int((-anomaly_score) * 50)))
        
        return {
            'is_anomaly': prediction == -1,
            'severity_score': severity,
            'anomaly_score': round(float(anomaly_score), 4),
            'features_analyzed': features
        }

    def analyze_logs(self, logs):
        """Analyze all logs and return threat scores"""
        print("\n🔍 ARGUS ML Engine: Analyzing logs...")
        results = []
        
        for i, log in enumerate(logs):
            result = self.predict(log)
            result['log_index'] = i
            result['event_type'] = log.get('event_type', 'unknown')
            result['source_ip'] = log.get('source_ip', 'unknown')
            result['timestamp'] = log.get('timestamp', 'unknown')
            
            status = "🔴 ANOMALY" if result['is_anomaly'] else "🟢 NORMAL"
            print(f"  Event {i+1} [{log.get('event_type')}]: {status} | Severity: {result['severity_score']}/100")
            results.append(result)
        
        return results


# Test it directly
if __name__ == "__main__":
    detector = ARGUSAnomalyDetector()
    detector.train()
    
    # Load logs
    with open("data/sample_logs.json") as f:
        logs = json.load(f)
    
    results = detector.analyze_logs(logs)
    
    print("\n" + "="*50)
    print("ARGUS ML ANOMALY DETECTION RESULTS")
    print("="*50)
    for r in results:
        print(f"\nEvent: {r['event_type']} from {r['source_ip']}")
        print(f"  Anomaly: {r['is_anomaly']}")
        print(f"  Severity Score: {r['severity_score']}/100")
        print(f"  Raw Anomaly Score: {r['anomaly_score']}")