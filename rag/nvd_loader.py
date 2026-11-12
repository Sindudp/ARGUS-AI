# rag/nvd_loader.py
# Purpose: fetch OFFICIAL CVE descriptions from NVD and load them into ChromaDB

import os
import sys
import json
import time
import requests
import chromadb

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rag.vector_store import ARGUSVectorStore

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = "data/nvd_cache.json"

CVE_IDS = [
    "CVE-2023-23397", "CVE-2022-26923", "CVE-2023-32315", "CVE-2023-4966",
    "CVE-2023-34362", "CVE-2023-27350", "CVE-2023-20198", "CVE-2022-30190",
    "CVE-2021-34527", "CVE-2023-28252", "CVE-2023-24880", "CVE-2020-1472",
    "CVE-2023-23376", "CVE-2023-34048", "CVE-2022-22954", "CVE-2023-44487",
    "CVE-2023-35708", "CVE-2023-36884", "CVE-2023-38831", "CVE-2023-29357",
]


def fetch_cve(cve_id):
    response = requests.get(API, params={"cveId": cve_id}, timeout=30)
    response.raise_for_status()
    vulns = response.json().get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0]["cve"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
    )

    score, severity = "0.0", "UNKNOWN"
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            score = str(m["cvssData"]["baseScore"])
            severity = m["cvssData"].get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
            break

    return {"id": cve_id, "description": description,
            "severity": severity, "cvss_score": score}


def load_all():
    cache = {}
    if os.path.exists(CACHE):
        with open(CACHE, encoding="utf-8") as f:
            cache = json.load(f)

    for cve_id in CVE_IDS:
        if cve_id in cache:
            continue
        print(f"Fetching {cve_id} from NVD...")
        try:
            item = fetch_cve(cve_id)
            if item:
                cache[cve_id] = item
        except Exception as e:
            print(f"  failed: {e}")
        time.sleep(7)  # NVD allows about 5 requests per 30 seconds without a key
        with open(CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2)

    return list(cache.values())


if __name__ == "__main__":
    cves = load_all()
    print(f"\nGot {len(cves)} official CVEs from NVD")

    # remove the old hand-written entries, then load the official ones
    client = chromadb.PersistentClient(path="./data/chromadb")
    try:
        client.delete_collection("cve_vulnerabilities")
    except Exception:
        pass

    store = ARGUSVectorStore()
    store.add_cves(cves)

    print("\nSample official entries:")
    for c in cves[:3]:
        print(f"  {c['id']} | {c['severity']} | {c['cvss_score']}")
        print(f"    {c['description'][:110]}...") 
