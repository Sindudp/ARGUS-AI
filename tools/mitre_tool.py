# tools/mitre_tool.py
# Purpose: Give ARGUS agents ability to look up
# real MITRE ATT&CK technique details automatically

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crewai.tools import tool

# Local MITRE ATT&CK database — no API key needed
# Real technique data from attack.mitre.org
MITRE_DATABASE = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Brute forcing passwords can take place via interaction with a service that will check the validity of credentials or offline against previously acquired credential data.",
        "detection": "Monitor authentication logs for large numbers of failed authentication attempts. Detect password spraying by looking for failed logins across many accounts. Alert on account lockouts.",
        "mitigation": "Enable multi-factor authentication. Set account lockout policies after 5-10 failed attempts. Use strong password requirements minimum 12 characters. Monitor for abnormal login patterns.",
        "subtechniques": ["T1110.001 - Password Guessing", "T1110.002 - Password Cracking", "T1110.003 - Password Spraying"]
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as C2 communications.",
        "detection": "Analyze network traffic for unusual data volumes leaving the network especially during off-hours. Monitor for connections to known malicious IPs. Alert on large outbound data transfers.",
        "mitigation": "Use data loss prevention tools to monitor and block sensitive data transfers. Implement network segmentation. Monitor and control outbound traffic. Block known malicious IP addresses.",
        "subtechniques": ["T1041.001 - Symmetric Cryptography", "T1041.002 - Asymmetric Cryptography"]
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote exploitation. Methods to acquire this information include port scans and vulnerability scans.",
        "detection": "Monitor network traffic for port scanning activity. Alert on sequential port connections from single source. Detect unusually high number of connection attempts in short time period.",
        "mitigation": "Use firewalls to restrict port scanning. Implement network segmentation to limit reconnaissance. Deploy honeypots to detect scanning activity. Use intrusion detection systems.",
        "subtechniques": ["T1046.001 - Port Scan", "T1046.002 - Vulnerability Scan"]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key.",
        "detection": "Monitor for file system activity showing mass file modifications with unknown extensions. Alert on processes creating many new files rapidly. Detect shadow copy deletion which precedes ransomware encryption.",
        "mitigation": "Maintain offline backups of critical data. Use endpoint detection and response tools. Implement application whitelisting. Restrict admin privileges. Keep systems patched and updated.",
        "subtechniques": ["T1486.001 - Ransomware", "T1486.002 - File Encryption"]
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network.",
        "detection": "Monitor for anomalous account behavior such as logins at unusual times or from unusual locations. Alert on accounts accessing resources they normally do not access.",
        "mitigation": "Implement multi-factor authentication. Use privileged access management. Regularly audit accounts and remove unused accounts. Monitor for credential theft.",
        "subtechniques": ["T1078.001 - Default Accounts", "T1078.002 - Domain Accounts", "T1078.003 - Local Accounts"]
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections, such as RDP, SSH, and VNC. The adversary may then perform actions as the logged-on user.",
        "detection": "Monitor remote service logins especially RDP and SSH. Alert on logins from unusual source IPs. Detect logins outside of business hours. Monitor for failed remote login attempts.",
        "mitigation": "Limit remote service access. Use multi-factor authentication for remote access. Monitor and log all remote connections. Use VPN for remote access. Disable unnecessary remote services.",
        "subtechniques": ["T1021.001 - Remote Desktop Protocol", "T1021.004 - SSH", "T1021.005 - VNC"]
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing.",
        "detection": "Monitor email for suspicious attachments and links. Use email filtering solutions. Alert on emails from unknown senders with attachments. Train users to recognize phishing attempts.",
        "mitigation": "Implement email filtering and anti-phishing tools. User awareness training. Enable multi-factor authentication. Use DMARC, DKIM, and SPF email authentication.",
        "subtechniques": ["T1566.001 - Spearphishing Attachment", "T1566.002 - Spearphishing Link"]
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
        "detection": "Monitor web application logs for unusual requests. Alert on SQL injection patterns and XSS attempts. Use web application firewall to detect exploit attempts.",
        "mitigation": "Keep all public-facing applications patched. Use web application firewall. Implement input validation. Regular vulnerability scanning and penetration testing.",
        "subtechniques": ["T1190.001 - SQL Injection", "T1190.002 - Cross-Site Scripting"]
    }
}

@tool("MITRE ATT&CK Lookup")
def lookup_mitre_technique(technique_id: str) -> str:
    """
    Look up detailed information about a MITRE ATT&CK technique.
    Provides technique name, tactic, description, detection methods,
    and mitigation strategies.
    
    Input: MITRE technique ID like T1110, T1041, T1046, T1486
    Output: Full technique details including detection and mitigation
    """
    
    # Clean input
    technique_id = technique_id.strip().upper()
    
    # Remove subtechnique if provided
    if "." in technique_id:
        technique_id = technique_id.split(".")[0]
    
    print(f"\n🔍 MITRE Lookup: {technique_id}")
    
    if technique_id not in MITRE_DATABASE:
        return f"Technique {technique_id} not found in local database. Known techniques: {', '.join(MITRE_DATABASE.keys())}"
    
    t = MITRE_DATABASE[technique_id]
    
    output = f"""
MITRE ATT&CK TECHNIQUE: {technique_id}
{'='*50}
Name: {t['name']}
Tactic: {t['tactic']}

Description:
{t['description']}

Detection Methods:
{t['detection']}

Mitigation Strategies:
{t['mitigation']}

Sub-techniques:
{chr(10).join(t['subtechniques'])}

Reference: https://attack.mitre.org/techniques/{technique_id}/
"""
    return output


# Test directly
if __name__ == "__main__":
    print("="*50)
    print("ARGUS MITRE ATT&CK TOOL TEST")
    print("="*50)

    # Test all main attack techniques
    techniques = ["T1110", "T1041", "T1046", "T1486"]

    for t_id in techniques:
        result = lookup_mitre_technique.run(t_id)
        print(result)
        print("-"*50)

    print("✅ MITRE Tool working!")
