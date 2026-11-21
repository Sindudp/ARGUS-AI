# data/log_generator.py
# Purpose: generate simulated attack logs for ARGUS-AI testing and demos

import json
import random
import os
from datetime import datetime, timedelta


class ARGUSLogGenerator:
    def __init__(self):
        self.internal_ips = ["192.168.1.{}".format(i) for i in range(1, 50)]
        self.external_ips = [
            "185.220.101.45",
            "45.142.212.100",
            "91.108.4.200",
            "194.165.16.11",
            "23.106.160.174",
        ] + ["10.10.10.{}".format(i) for i in range(1, 20)]
        self.usernames = ["admin", "administrator", "root", "sindu", "user1", "test", "guest"]

    def generate_timestamp(self, base_time=None, offset_seconds=0):
        if base_time is None:
            base_time = datetime.now()
        t = base_time + timedelta(seconds=offset_seconds)
        return t.strftime("%Y-%m-%d %H:%M:%S")

    def generate_brute_force(self, attacker_ip=None, target_ip=None, count=50):
        attacker_ip = attacker_ip or random.choice(self.internal_ips)
        target_ip = target_ip or "10.0.0.1"
        logs = []
        base_time = datetime.now()
        for i in range(count - 1):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 2),
                "source_ip": attacker_ip, "dest_ip": target_ip,
                "event_type": "login_attempt", "status": "failed",
                "count": i + 1, "user": random.choice(self.usernames),
                "attack_type": "BRUTE_FORCE",
            })
        logs.append({
            "timestamp": self.generate_timestamp(base_time, count * 2),
            "source_ip": attacker_ip, "dest_ip": target_ip,
            "event_type": "login_attempt", "status": "success",
            "count": count, "user": "admin", "attack_type": "BRUTE_FORCE_SUCCESS",
        })
        return logs

    def generate_data_exfiltration(self, source_ip=None, dest_ip=None):
        source_ip = source_ip or random.choice(self.internal_ips)
        dest_ip = dest_ip or "185.220.101.45"
        base_time = datetime.now()
        logs = []
        for i in range(3):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 30),
                "source_ip": source_ip, "dest_ip": dest_ip,
                "event_type": "data_transfer",
                "bytes_sent": random.randint(1000, 50000), "port": 443,
                "attack_type": "RECON_TRANSFER",
            })
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 120),
            "source_ip": source_ip, "dest_ip": dest_ip,
            "event_type": "data_transfer",
            "bytes_sent": random.randint(100000000, 600000000), "port": 443,
            "attack_type": "DATA_EXFILTRATION",
        })
        return logs

    def generate_port_scan(self, attacker_ip=None, target_ip=None):
        attacker_ip = attacker_ip or random.choice(self.internal_ips)
        target_ip = target_ip or "10.0.0.1"
        return [{
            "timestamp": self.generate_timestamp(),
            "source_ip": attacker_ip, "dest_ip": target_ip,
            "event_type": "port_scan",
            "ports_scanned": random.randint(500, 1000),
            "status": "detected", "attack_type": "RECONNAISSANCE",
        }]

    def generate_ransomware(self, infected_ip=None):
        infected_ip = infected_ip or random.choice(self.internal_ips)
        base_time = datetime.now()
        logs = [{
            "timestamp": self.generate_timestamp(base_time),
            "source_ip": infected_ip, "dest_ip": "10.0.0.1",
            "event_type": "malicious_process", "process": "ransomware.exe",
            "files_encrypted": 0, "attack_type": "RANSOMWARE_START",
        }]
        for i in range(5):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 10),
                "source_ip": infected_ip,
                "dest_ip": random.choice(self.internal_ips),
                "event_type": "lateral_movement",
                "files_encrypted": (i + 1) * 3000,
                "extension": ".argus_locked",
                "attack_type": "RANSOMWARE_SPREAD",
            })
        return logs

    def generate_web_exploit(self, attacker_ip=None, target_ip=None):
        """An exploit attempt against a web application (matches a CVE in the knowledge base)."""
        attacker_ip = attacker_ip or random.choice(self.external_ips)
        target_ip = target_ip or "10.0.0.8"
        return [{
            "timestamp": self.generate_timestamp(),
            "source_ip": attacker_ip, "dest_ip": target_ip,
            "event_type": "web_request", "status": "detected", "count": 1,
            "description": "SQL injection attempt against the file transfer web application",
            "attack_type": "WEB_APP_EXPLOIT",
        }]

    def generate_full_scenario(self, scenario="all"):
        logs = []
        if scenario in ("brute_force", "all"):
            logs.extend(self.generate_brute_force())
        if scenario in ("exfiltration", "all"):
            logs.extend(self.generate_data_exfiltration())
        if scenario in ("port_scan", "all"):
            logs.extend(self.generate_port_scan())
        if scenario in ("ransomware", "all"):
            logs.extend(self.generate_ransomware())
        if scenario in ("web_exploit", "all"):
            logs.extend(self.generate_web_exploit())
        return logs

    def save_logs(self, logs, filename="data/generated_logs.json"):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
        print(f"Saved {len(logs)} logs to {filename}")
        return filename


if __name__ == "__main__":
    print("=" * 50)
    print("ARGUS-AI LOG GENERATOR")
    print("=" * 50)
    generator = ARGUSLogGenerator()
    logs = generator.generate_full_scenario("all")
    print(f"Generated {len(logs)} attack log events")
    counts = {}
    for log in logs:
        t = log.get("attack_type", "UNKNOWN")
        counts[t] = counts.get(t, 0) + 1
    for attack, count in counts.items():
        print(f"  {attack}: {count} events")
    generator.save_logs(logs)
