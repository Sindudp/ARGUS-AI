# data/log_generator.py
# Purpose: Generate realistic attack log data for
# ARGUS-AI testing and demo purposes

import json
import random
import os
from datetime import datetime, timedelta

class ARGUSLogGenerator:
    def __init__(self):
        # Realistic IP ranges
        self.internal_ips = [
            "192.168.1.{}".format(i) for i in range(1, 50)
        ]
        self.external_ips = [
        "185.220.101.45",
        "45.142.212.100",
        "91.108.4.200",
        "194.165.16.11",
        "23.106.160.174"
        ] + ["10.10.10.{}".format(i) for i in range(1, 20)]

        self.usernames = [
            "admin", "administrator", "root",
            "sindu", "user1", "test", "guest"
        ]

    def generate_timestamp(self, base_time=None, offset_seconds=0):
        if base_time is None:
            base_time = datetime.now()
        t = base_time + timedelta(seconds=offset_seconds)
        return t.strftime("%Y-%m-%d %H:%M:%S")

    # Attack Scenario 1 — Brute Force
    def generate_brute_force(self, attacker_ip=None, target_ip=None, count=50):
        if not attacker_ip:
            attacker_ip = random.choice(self.internal_ips)
        if not target_ip:
            target_ip = "10.0.0.1"

        logs = []
        base_time = datetime.now()

        # Failed attempts
        for i in range(count - 1):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 2),
                "source_ip": attacker_ip,
                "dest_ip": target_ip,
                "event_type": "login_attempt",
                "status": "failed",
                "count": i + 1,
                "user": random.choice(self.usernames),
                "attack_type": "BRUTE_FORCE"
            })

        # Successful login after brute force
        logs.append({
            "timestamp": self.generate_timestamp(base_time, count * 2),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "event_type": "login_attempt",
            "status": "success",
            "count": count,
            "user": "admin",
            "attack_type": "BRUTE_FORCE_SUCCESS"
        })

        return logs

    # Attack Scenario 2 — Data Exfiltration
    def generate_data_exfiltration(self, source_ip=None, dest_ip=None):
        if not source_ip:
            source_ip = random.choice(self.internal_ips)
        if not dest_ip:
            dest_ip = "185.220.101.45"

        base_time = datetime.now()
        logs = []

        # Small transfers first — reconnaissance
        for i in range(3):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 30),
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "event_type": "data_transfer",
                "bytes_sent": random.randint(1000, 50000),
                "port": 443,
                "attack_type": "RECON_TRANSFER"
            })

        # Large exfiltration
        logs.append({
            "timestamp": self.generate_timestamp(base_time, 120),
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "event_type": "data_transfer",
            "bytes_sent": random.randint(100000000, 600000000),
            "port": 443,
            "attack_type": "DATA_EXFILTRATION"
        })

        return logs

    # Attack Scenario 3 — Port Scan
    def generate_port_scan(self, attacker_ip=None, target_ip=None):
        if not attacker_ip:
            attacker_ip = random.choice(self.internal_ips)
        if not target_ip:
            target_ip = "10.0.0.1"

        base_time = datetime.now()

        return [{
            "timestamp": self.generate_timestamp(base_time),
            "source_ip": attacker_ip,
            "dest_ip": target_ip,
            "event_type": "port_scan",
            "ports_scanned": random.randint(500, 1000),
            "status": "detected",
            "attack_type": "RECONNAISSANCE"
        }]

    # Attack Scenario 4 — Ransomware
    def generate_ransomware(self, infected_ip=None):
        if not infected_ip:
            infected_ip = random.choice(self.internal_ips)

        base_time = datetime.now()
        logs = []

        # Initial access
        logs.append({
            "timestamp": self.generate_timestamp(base_time),
            "source_ip": infected_ip,
            "dest_ip": "10.0.0.1",
            "event_type": "malicious_process",
            "process": "ransomware.exe",
            "files_encrypted": 0,
            "attack_type": "RANSOMWARE_START"
        })

        # Spreading
        for i in range(5):
            logs.append({
                "timestamp": self.generate_timestamp(base_time, i * 10),
                "source_ip": infected_ip,
                "dest_ip": random.choice(self.internal_ips),
                "event_type": "lateral_movement",
                "files_encrypted": (i + 1) * 3000,
                "extension": ".argus_locked",
                "attack_type": "RANSOMWARE_SPREAD"
            })

        return logs

    # Generate full attack scenario
    def generate_full_scenario(self, scenario="all"):
        logs = []

        if scenario == "brute_force" or scenario == "all":
            logs.extend(self.generate_brute_force())

        if scenario == "exfiltration" or scenario == "all":
            logs.extend(self.generate_data_exfiltration())

        if scenario == "port_scan" or scenario == "all":
            logs.extend(self.generate_port_scan())

        if scenario == "ransomware" or scenario == "all":
            logs.extend(self.generate_ransomware())

        return logs

    def save_logs(self, logs, filename="data/generated_logs.json"):
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w") as f:
            json.dump(logs, f, indent=2)
        print(f"✅ Saved {len(logs)} logs to {filename}")
        return filename


# Run directly to generate logs
if __name__ == "__main__":
    print("="*50)
    print("ARGUS-AI LOG GENERATOR")
    print("="*50)

    generator = ARGUSLogGenerator()

    # Generate all attack scenarios
    print("\n🔧 Generating realistic attack logs...")
    logs = generator.generate_full_scenario("all")

    print(f"✅ Generated {len(logs)} attack log events!")
    print("\nBreakdown:")
    attack_types = {}
    for log in logs:
        t = log.get("attack_type", "UNKNOWN")
        attack_types[t] = attack_types.get(t, 0) + 1

    for attack, count in attack_types.items():
        print(f"  → {attack}: {count} events")

    # Save to file
    generator.save_logs(logs)

    # Show sample
    print("\n📋 Sample log event:")
    print(json.dumps(logs[0], indent=2))

    print("\n✅ Log Generator complete!")