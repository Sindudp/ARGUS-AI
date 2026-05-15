from crewai import Agent, Task, Crew, LLM
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Setup Groq LLM
llm = LLM(
    model="groq/llama-3.3-70b-versatile",
    api_key=os.getenv("GROQ_API_KEY")
)

# Load logs
with open("data/sample_logs.json") as f:
    logs = json.load(f)

# ─────────────────────────────────────────
# AGENT 1 — Triage Agent (from Day 1)
# ─────────────────────────────────────────
triage_agent = Agent(
    role="ARGUS Triage Specialist",
    goal="Analyze security logs and identify threats with severity scores",
    backstory="""You are ARGUS — an elite AI security analyst with 15 years 
    of SOC experience. You analyze logs, detect attack patterns like brute 
    force, data exfiltration, and port scans. You assign severity scores 
    from 0-100 and classify every threat instantly.""",
    llm=llm,
    verbose=True
)

# ─────────────────────────────────────────
# AGENT 2 — Investigation Agent (NEW!)
# ─────────────────────────────────────────
investigation_agent = Agent(
    role="ARGUS Senior Security Investigator",
    goal="Perform deep root cause analysis on detected threats and provide comprehensive investigation reports",
    backstory="""You are ARGUS's senior investigator with 20 years of 
    cybersecurity forensics experience. You specialize in understanding 
    the full attack chain, identifying attacker motivation, determining 
    blast radius, and providing actionable intelligence. You think like 
    an attacker to defend like an expert. You have deep knowledge of 
    APT groups, attack patterns, and real-world breach case studies.""",
    llm=llm,
    verbose=True
)

# ─────────────────────────────────────────
# TASK 1 — Triage Task
# ─────────────────────────────────────────
triage_task = Task(
    description=f"""
    Analyze these security logs from ARGUS monitoring system:
    {json.dumps(logs, indent=2)}
    
    For each suspicious event:
    1. Identify the attack type
    2. Assign severity score (0-100)
    3. Map to MITRE ATT&CK technique
    4. Recommend immediate action
    
    Format your response clearly for each threat found.
    """,
    expected_output="""A structured threat report with:
    - Attack type for each event
    - Severity score 0-100
    - MITRE ATT&CK technique ID and name
    - Recommended action""",
    agent=triage_agent
)

# ─────────────────────────────────────────
# TASK 2 — Investigation Task (NEW!)
# ─────────────────────────────────────────
investigation_task = Task(
    description="""
    Based on the triage report provided, perform a deep investigation on 
    the most critical threats (severity score above 70).
    
    For each critical threat investigate:
    1. ATTACK CHAIN: What is the full sequence of events? 
       What happened before, during, and what will happen next?
    2. ATTACKER PROFILE: What kind of attacker is this? 
       Script kiddie, insider threat, APT group, or cybercriminal?
    3. BLAST RADIUS: What systems, data, and users are at risk?
    4. ROOT CAUSE: Why was this attack possible? 
       What vulnerability or misconfiguration allowed it?
    5. EVIDENCE: What forensic evidence should be collected immediately?
    6. REMEDIATION: Step by step fix to stop this attack right now.
    7. PREVENTION: How to prevent this from happening again?
    
    Write a professional incident investigation report.
    """,
    expected_output="""A professional incident investigation report with:
    - Full attack chain analysis
    - Attacker profile assessment  
    - Blast radius assessment
    - Root cause identification
    - Evidence collection checklist
    - Step by step remediation plan
    - Prevention recommendations""",
    agent=investigation_agent,
    context=[triage_task]
)

# ─────────────────────────────────────────
# LAUNCH ARGUS CREW
# ─────────────────────────────────────────
print("\n" + "="*60)
print("   ARGUS — Autonomous Guardian System")
print("   Day 2: Triage + Investigation Agents Active")
print("="*60 + "\n")

crew = Crew(
    agents=[triage_agent, investigation_agent],
    tasks=[triage_task, investigation_task],
    verbose=True
)

result = crew.kickoff()

print("\n" + "="*60)
print("   ARGUS FULL INVESTIGATION REPORT")
print("="*60)
print(result)

# Save report to file
with open("data/investigation_report.txt", "w") as f:
    f.write("ARGUS INVESTIGATION REPORT\n")
    f.write("="*60 + "\n")
    f.write(str(result))
    
print("\nReport saved to data/investigation_report.txt")