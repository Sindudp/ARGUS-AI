# tools/threat_intel_tool.py
# Purpose: lets the Investigation Agent search the CVE knowledge base

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crewai.tools import tool
from rag.cve_loader import ARGUSCVELoader

print("🔧 Threat Intel Tool: Loading CVE database...")
cve_loader = ARGUSCVELoader()
cve_loader.load_into_chromadb()
print("✅ Threat Intel Tool: Ready!")

MIN_SCORE = 0.50  # below this, we say "no strong match"


@tool("CVE Intelligence Search")
def search_cve_database(attack_description: str) -> str:
    """
    Search the CVE vulnerability database for software weaknesses that
    could relate to the given attack description. Use it when investigating
    a security event. It returns only strong text matches. If nothing
    matches, it says so.

    Input: description of the weakness or attack
    Output: possible matching CVEs with severity and description
    """
    print(f"\n🔍 CVE Search: {attack_description[:50]}...")
    results = cve_loader.search_threat(attack_description)
    strong = [r for r in results if (1 - r['distance']) >= MIN_SCORE]

    if not strong:
        return ("No strongly matching CVE found in the knowledge base. "
                "This behaviour may not be tied to a specific software "
                "vulnerability; rely on the MITRE ATT&CK technique instead.")

    output = "POSSIBLE CVE MATCHES (text similarity only, not proof of exploitation):\n\n"
    for i, r in enumerate(strong, 1):
        output += (f"Match {i}: {r['cve_id']} | {r['severity']} | "
                   f"CVSS {r['cvss_score']} | similarity {round(1 - r['distance'], 3)}\n")
        output += f"  {r['description'][:300]}\n\n"
    return output


if __name__ == "__main__":
    tests = [
        "47 failed login attempts on admin account from single IP",
        "files being encrypted rapidly across network systems",
        "SQL injection in a file transfer application used to steal files",
        "authentication bypass on a web administration console",
    ]
    for q in tests:
        print("\nQUERY:", q)
        for r in cve_loader.search_threat(q):
            print(f"  {r['cve_id']}  similarity={round(1 - r['distance'], 3)}")