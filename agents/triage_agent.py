import os
import sys
import json
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.groq_patch  # fixes the Groq + CrewAI cache_breakpoint error

from crewai import Agent, Task, Crew, LLM

load_dotenv()

llm = LLM(
    model=f"groq/{os.getenv('MODEL_NAME', 'openai/gpt-oss-120b')}",
    api_key=os.getenv("GROQ_API_KEY")
)

with open("data/sample_logs.json", encoding="utf-8") as f:
    logs = json.load(f)

triage_agent = Agent(
    role="ARGUS Triage Specialist",
    goal="Analyze security logs and identify threats with severity scores",
    backstory="You are a SOC analyst with 15 years of experience. You detect "
              "attack patterns such as brute force, data exfiltration and port "
              "scans, assign severity scores from 0 to 100 and classify every threat.",
    llm=llm,
    verbose=True
)

triage_task = Task(
    description=f"""
Analyze these security logs from the ARGUS monitoring system:
{json.dumps(logs, indent=2)}

For each suspicious event:
1. Identify the attack type
2. Assign a severity score (0-100)
3. Map it to a MITRE ATT&CK technique
4. Recommend an immediate action

RULES:
- Use only the fields shown in the logs. Do not assume a protocol, tool or product that does not appear in them.
""",
    expected_output="A structured threat report with attack type, severity score, "
                    "MITRE ATT&CK technique ID and name, and recommended action",
    agent=triage_agent
)

print("\n" + "=" * 50)
print("   ARGUS - Triage Agent")
print("=" * 50 + "\n")

crew = Crew(agents=[triage_agent], tasks=[triage_task], verbose=True)
result = crew.kickoff()

print("\n" + "=" * 50)
print("   ARGUS THREAT REPORT")
print("=" * 50)
print(result)