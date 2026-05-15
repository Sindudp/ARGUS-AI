 
from crewai import Agent, Task, Crew, LLM
import json
import os
from dotenv import load_dotenv
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.anomaly_detector import ARGUSAnomalyDetector

load_dotenv()

# Setup Groq LLM
llm = LLM(
    model="groq/llama-3.3-70b-versatile",
    api_key=os.getenv("GROQ_API_KEY")
)

# Load logs
with open("data/sample_logs.json") as f:
    logs = json.load(f)

# Run ML detection first
print("\n" + "="*60)
print("   ARGUS — Autonomous Guardian System")
print("   Day 3: ML Detection + 3 Agents Active")
print("="*60)

detector = ARGUSAnomalyDetector()
detector.train()
ml_results = detector.analyze_logs(logs)

# Fix bool serialization for JSON
for r in ml_results:
    r['is_anomaly'] = bool(r['is_anomaly'])

# Filter only anomalies
anomalies = [r for r in ml_results if r['is_anomaly']]
print(f"\n🔴 ML Engine found {len(anomalies)} anomalies out of {len(logs)} events")

# ─────────────────────────────────────────
# AGENT 1 — Triage Agent
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
# AGENT 2 — Investigation Agent
# ─────────────────────────────────────────
investigation_agent = Agent(
    role="ARGUS Senior Security Investigator",
    goal="Perform deep root cause analysis on detected threats",
    backstory="""You are ARGUS's senior investigator with 20 years of 
    cybersecurity forensics experience. You identify attack chains, 
    attacker profiles, blast radius, and root causes.""",
    llm=llm,
    verbose=True
)

# ─────────────────────────────────────────
# AGENT 3 — Response Agent (NEW!)
# ─────────────────────────────────────────
response_agent = Agent(
    role="ARGUS Incident Response Commander",
    goal="Generate immediate containment playbooks and response actions for confirmed threats",
    backstory="""You are ARGUS's incident response commander with 25 years 
    of experience handling major cyber incidents at Fortune 500 companies. 
    You have responded to nation-state attacks, ransomware outbreaks, and 
    insider threats. You generate precise, actionable containment playbooks 
    that security teams can execute immediately. Every second counts in 
    incident response — your playbooks are clear, numbered, and executable 
    without ambiguity. You also write executive summaries that non-technical 
    management can understand.""",
    llm=llm,
    verbose=True
)

# ─────────────────────────────────────────
# TASK 1 — Triage
# ─────────────────────────────────────────
triage_task = Task(
    description=f"""
    The ARGUS ML Engine has detected {len(anomalies)} anomalies.
    
    ML Detection Results:
    {json.dumps(ml_results, indent=2)}
    
    Original Log Events:
    {json.dumps(logs, indent=2)}
    
    For each anomaly detected by ML:
    1. Confirm or reject the ML finding
    2. Identify the attack type
    3. Assign final severity score combining ML score + your analysis
    4. Map to MITRE ATT&CK technique
    """,
    expected_output="Confirmed threat list with severity scores and MITRE mappings",
    agent=triage_agent
)

# ─────────────────────────────────────────
# TASK 2 — Investigation
# ─────────────────────────────────────────
investigation_task = Task(
    description="""
    Based on the triage report, investigate the most critical threats.
    
    For each critical threat (severity above 70):
    1. Full attack chain analysis
    2. Attacker profile
    3. Blast radius
    4. Root cause
    5. Key evidence to collect
    """,
    expected_output="Deep investigation report with attack chain and root cause",
    agent=investigation_agent,
    context=[triage_task]
)

# ─────────────────────────────────────────
# TASK 3 — Response (NEW!)
# ─────────────────────────────────────────
response_task = Task(
    description="""
    Based on the triage and investigation reports, generate immediate 
    response playbooks for each confirmed threat.
    
    For each threat generate:
    
    1. IMMEDIATE ACTIONS (first 15 minutes):
       - Exact commands or steps to contain the threat RIGHT NOW
       - Which systems to isolate
       - Which IPs to block
       - Which accounts to disable
    
    2. CONTAINMENT PLAYBOOK (step by step numbered list):
       - Every action the security team must take in order
       - Who is responsible (SOC analyst, system admin, management)
       - Time estimate for each step
    
    3. EXECUTIVE SUMMARY (non-technical, 3 sentences):
       - What happened in plain English
       - Business impact
       - What we are doing about it
    
    4. SEVERITY RATING: CRITICAL / HIGH / MEDIUM / LOW
    
    5. ESTIMATED RECOVERY TIME
    
    Format as a professional incident response playbook.
    """,
    expected_output="""Complete incident response playbook with:
    - Immediate containment actions
    - Step by step playbook
    - Executive summary
    - Severity rating
    - Recovery time estimate""",
    agent=response_agent,
    context=[triage_task, investigation_task]
)

# ─────────────────────────────────────────
# LAUNCH FULL ARGUS CREW
# ─────────────────────────────────────────
crew = Crew(
    agents=[triage_agent, investigation_agent, response_agent],
    tasks=[triage_task, investigation_task, response_task],
    verbose=True
)

result = crew.kickoff()

print("\n" + "="*60)
print("   ARGUS COMPLETE INCIDENT RESPONSE PLAYBOOK")
print("="*60)
print(result)

# Save everything
os.makedirs("data", exist_ok=True)
with open("data/response_playbook.txt", "w") as f:
    f.write("ARGUS INCIDENT RESPONSE PLAYBOOK\n")
    f.write("="*60 + "\n")
    f.write(str(result))

with open("data/ml_results.json", "w") as f:
    json.dump(ml_results, f, indent=2)

print("\n✅ Playbook saved to data/response_playbook.txt")
print("✅ ML results saved to data/ml_results.json")