import os
import sys
import json
from dotenv import load_dotenv

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.groq_patch  # fixes the Groq + CrewAI cache_breakpoint error

from crewai import Agent, Task, Crew, LLM
from tools.anomaly_detector import ARGUSAnomalyDetector

load_dotenv()

llm = LLM(
    model=f"groq/{os.getenv('MODEL_NAME', 'openai/gpt-oss-120b')}",
    api_key=os.getenv("GROQ_API_KEY")
)

with open("data/sample_logs.json", encoding="utf-8") as f:
    logs = json.load(f)

print("\n" + "=" * 60)
print("   ARGUS - ML detection + 3 agents")
print("=" * 60)

detector = ARGUSAnomalyDetector()
detector.train()
ml_results = detector.analyze_logs(logs)

for r in ml_results:
    r['is_anomaly'] = bool(r['is_anomaly'])

anomalies = [r for r in ml_results if r['is_anomaly']]
print(f"\nML engine found {len(anomalies)} anomalies out of {len(logs)} events")

triage_agent = Agent(
    role="ARGUS Triage Specialist",
    goal="Analyze security logs and identify threats with severity scores",
    backstory="You are a SOC analyst with 15 years of experience. You classify "
              "attacks and assign severity scores from 0 to 100.",
    llm=llm,
    verbose=True
)

investigation_agent = Agent(
    role="ARGUS Senior Security Investigator",
    goal="Perform root cause analysis on detected threats",
    backstory="You are a forensics expert. You identify attack chains, blast "
              "radius and root causes, and you never invent facts.",
    llm=llm,
    verbose=True
)

response_agent = Agent(
    role="ARGUS Incident Response Commander",
    goal="Generate containment playbooks for confirmed threats",
    backstory="You have led incident response at large companies. Your playbooks "
              "are numbered, short and executable, and management summaries are "
              "written in plain English.",
    llm=llm,
    verbose=True
)

triage_task = Task(
    description=f"""
The ARGUS ML engine detected {len(anomalies)} anomalies.

ML results:
{json.dumps(ml_results, indent=2)}

Original log events:
{json.dumps(logs, indent=2)}

For each anomaly:
1. Confirm or reject the ML finding
2. Identify the attack type
3. Give a final severity score combining the ML score and your analysis
4. Map it to a MITRE ATT&CK technique

RULES:
- Use only the fields shown. Do not assume a protocol, tool or product that does not appear in the data.
""",
    expected_output="Confirmed threat list with severity scores and MITRE mappings",
    agent=triage_agent
)

investigation_task = Task(
    description="""
Based on the triage report, investigate the most critical threats (severity above 70).
For each one give: attack chain, attacker profile, blast radius, root cause, key evidence.

RULES:
- Use only facts from the triage report. Do not invent malware names, tools, products or attacker groups.
- If something cannot be determined from the logs, write 'Cannot be determined from the logs'.
- Label any inference with 'Likely:'.
""",
    expected_output="Investigation report with attack chain and root cause",
    agent=investigation_agent,
    context=[triage_task]
)

response_task = Task(
    description="""
Based on the triage and investigation reports, write a response playbook for each
confirmed threat. For each threat give:
1. Immediate actions (first 15 minutes)
2. A numbered containment playbook with owner and time for each step
3. A 3-sentence executive summary in plain English
4. A severity rating (CRITICAL / HIGH / MEDIUM / LOW)
5. An estimated recovery time

RULE: Base each playbook only on the triage and investigation results. Do not mention a CVE, malware name or product that does not appear in them. Describe how an attack happened only with the word 'Likely', unless the data shows it directly.
""",
    expected_output="Incident response playbook with immediate actions, steps, "
                    "executive summary, severity and recovery time",
    agent=response_agent,
    context=[triage_task, investigation_task]
)

crew = Crew(
    agents=[triage_agent, investigation_agent, response_agent],
    tasks=[triage_task, investigation_task, response_task],
    verbose=True
)

result = crew.kickoff()

print("\n" + "=" * 60)
print("   ARGUS INCIDENT RESPONSE PLAYBOOK")
print("=" * 60)
print(result)

os.makedirs("data", exist_ok=True)
with open("data/response_playbook.txt", "w", encoding="utf-8") as f:
    f.write("ARGUS INCIDENT RESPONSE PLAYBOOK\n")
    f.write("=" * 60 + "\n")
    f.write(str(result))

with open("data/ml_results.json", "w", encoding="utf-8") as f:
    json.dump(ml_results, f, indent=2)

print("\nPlaybook saved to data/response_playbook.txt")
print("ML results saved to data/ml_results.json")