import os
import sys
import json
from dotenv import load_dotenv

# Must come BEFORE "import tools..." so Python can find the tools/ folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.groq_patch  # fixes the Groq + CrewAI cache_breakpoint error

from crewai import Agent, Task, Crew, LLM

load_dotenv()

# Setup Groq LLM (model name comes from .env, MODEL_NAME=...)
llm = LLM(
    model=f"groq/{os.getenv('MODEL_NAME', 'openai/gpt-oss-120b')}",
    api_key=os.getenv("GROQ_API_KEY")
)

# Load logs (run this script from D:\ARGUS so this relative path works)
with open("data/sample_logs.json", encoding="utf-8") as f:
    logs = json.load(f)

# Shared anti-hallucination rules, used in the agent AND the task
RULES = """RULES:
    - Use only facts from the triage report. Do not invent malware names, tools, products or attacker groups that are not in it.
    - If something cannot be determined from the logs, write 'Cannot be determined from the logs'.
    - Label any inference with 'Likely:'."""

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
    goal="Perform deep root cause analysis on detected threats and provide comprehensive investigation reports",
    backstory=f"""You are ARGUS's senior investigator with 20 years of
    cybersecurity forensics experience. You specialize in understanding
    the full attack chain, identifying attacker motivation, determining
    blast radius, and providing actionable intelligence. You think like
    an attacker to defend like an expert.
    {RULES}""",
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
# TASK 2 — Investigation Task
# ─────────────────────────────────────────
investigation_task = Task(
    description=f"""
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
    {RULES}
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
if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("   ARGUS — Autonomous Guardian System")
    print("   Day 2: Triage + Investigation Agents Active")
    print("=" * 60 + "\n")

    crew = Crew(
        agents=[triage_agent, investigation_agent],
        tasks=[triage_task, investigation_task],
        verbose=True
    )

    result = crew.kickoff()

    print("\n" + "=" * 60)
    print("   ARGUS FULL INVESTIGATION REPORT")
    print("=" * 60)
    print(result)

    # Save report to file (utf-8 so Windows can store special characters)
    os.makedirs("data", exist_ok=True)
    with open("data/investigation_report.txt", "w", encoding="utf-8") as f:
        f.write("ARGUS INVESTIGATION REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(str(result))

    print("\nReport saved to data/investigation_report.txt")
