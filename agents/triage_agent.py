 
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

# ARGUS Triage Agent
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

# Triage Task
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

# Launch ARGUS
print("\n" + "="*50)
print("   ARGUS — Autonomous Guardian System")
print("   Initiating threat analysis...")
print("="*50 + "\n")

crew = Crew(
    agents=[triage_agent],
    tasks=[triage_task],
    verbose=True
)

result = crew.kickoff()

print("\n" + "="*50)
print("   ARGUS THREAT REPORT")
print("="*50)
print(result)