# tools/threat_intel_tool.py
# Purpose: Give Investigation Agent ability to search
# ChromaDB CVE database automatically during investigation

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crewai.tools import tool
from rag.cve_loader import ARGUSCVELoader

# Initialize CVE loader once — loads 20 CVEs into ChromaDB
print("🔧 Threat Intel Tool: Loading CVE database...")
cve_loader = ARGUSCVELoader()
cve_loader.load_into_chromadb()
print("✅ Threat Intel Tool: Ready!")

@tool("CVE Intelligence Search")
def search_cve_database(attack_description: str) -> str:
    """
    Search the CVE vulnerability database for threats matching
    the given attack description. Use this tool when investigating
    any suspicious security event to find matching vulnerabilities,
    their severity scores, and recommended fixes.
    
    Input: description of the attack or suspicious behavior
    Output: matching CVEs with severity and description
    """
    
    print(f"\n🔍 CVE Search: {attack_description[:50]}...")
    
    # Search ChromaDB for matching CVEs
    results = cve_loader.search_threat(attack_description)
    
    if not results:
        return "No matching CVEs found in database."
    
    # Format results for the agent
    output = "MATCHING CVE VULNERABILITIES FOUND:\n\n"
    
    for i, r in enumerate(results, 1):
        output += f"Match {i}:\n"
        output += f"  CVE ID: {r['cve_id']}\n"
        output += f"  Severity: {r['severity']}\n"
        output += f"  CVSS Score: {r['cvss_score']}/10\n"
        output += f"  Description: {r['description']}\n"
        output += f"  Relevance Score: {round(1 - r['distance'], 3)}\n"
        output += "\n"
    
    output += "Use these CVEs to provide specific, expert-level threat analysis."
    return output


# Test the tool directly
if __name__ == "__main__":
    print("\n" + "="*50)
    print("THREAT INTEL TOOL TEST")
    print("="*50)
    
    # Test 1 — brute force
    print("\n🔴 Testing brute force search:")
    result = search_cve_database.run(
        "47 failed login attempts on admin account from single IP"
    )
    print(result)
    
    # Test 2 — ransomware
    print("\n💀 Testing ransomware search:")
    result = search_cve_database.run(
        "files being encrypted rapidly across network systems"
    )
    print(result)
    
    print("✅ Threat Intel Tool working!")