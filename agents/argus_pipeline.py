
import os
import sys
import json
from collections import defaultdict
from dotenv import load_dotenv


sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tools.groq_patch 

from crewai import Agent, Task, Crew, LLM
from tools.threat_intel_tool import search_cve_database
from tools.mitre_tool import lookup_mitre_technique

load_dotenv()

llm = LLM(
    model=f"groq/{os.getenv('MODEL_NAME', 'openai/gpt-oss-120b')}",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0.2
)


def summarize_logs(logs):
    # Group 61 raw events into a few lines the LLM can handle
    groups = defaultdict(list)
    for log in logs:
        key = (log.get("attack_type", "UNKNOWN"), log["source_ip"])
        groups[key].append(log)

    summary = []
    for (attack_type, source_ip), items in groups.items():
        entry = {
            "attack_type": attack_type,
            "source_ip": source_ip,
            "dest_ip": items[0]["dest_ip"],
            "event_type": items[0]["event_type"],
            "event_count": len(items),
            "first_seen": items[0]["timestamp"],
            "last_seen": items[-1]["timestamp"],
        }
        for field in ("bytes_sent", "ports_scanned", "files_encrypted"):
            values = [i[field] for i in items if field in i]
            if values:
                entry["max_" + field] = max(values)
        summary.append(entry)
    return summary


# Load logs made by log_generator.py
log_path = "data/generated_logs.json"
if not os.path.exists(log_path):
    print("Run python data/log_generator.py first!")
    sys.exit()

with open(log_path) as f:
    raw_logs = json.load(f)

summary = summarize_logs(raw_logs)
print(f"Raw events: {len(raw_logs)} -> Summarized into {len(summary)} groups")

# ---------------- AGENTS ----------------
triage_agent = Agent(
    role="ARGUS Triage Specialist",
    goal="Classify security events and score their severity from 0 to 100",
    backstory="You are a SOC analyst with 15 years of experience. "
              "You classify attacks quickly and assign MITRE ATT&CK technique IDs.",
    llm=llm,
    verbose=True
)

investigation_agent = Agent(
    role="ARGUS Senior Security Investigator",
    goal="Investigate the most severe threats using CVE and MITRE tools",
    backstory="You are a forensics expert. You never guess - you always "
              "look up CVEs and MITRE techniques with your tools before writing.",
    tools=[search_cve_database, lookup_mitre_technique],
    llm=llm,
    verbose=True,
    max_iter=8
)

response_agent = Agent(
    role="ARGUS Incident Response Commander",
    goal="Write clear containment playbooks for confirmed threats",
    backstory="You have led incident response at large companies. "
              "Your playbooks are numbered, short and executable.",
    llm=llm,
    verbose=True
)

# ---------------- TASKS ----------------
triage_task = Task(
    description=f"""Here is a summary of security events:
{json.dumps(summary, indent=2)}

For each group give: attack type, severity score (0-100),
and the MITRE ATT&CK technique ID (for example T1110).""",
    expected_output="A table of threats with severity and MITRE technique ID",
    agent=triage_agent
)

investigation_task = Task(
    description="""From the triage result pick the 3 MOST SEVERE threats.
For each one:
1. Call the 'CVE Intelligence Search' tool with a short description of the attack.
2. Call the 'MITRE ATT&CK Lookup' tool with the technique ID.
3. Write: attack chain, likely attacker type, matching CVE, and root cause.""",
    expected_output="Investigation report for 3 threats that cites CVE IDs and MITRE details",
    agent=investigation_agent,
    context=[triage_task]
)

response_task = Task(
    description="""Using the triage and investigation results, write a response
playbook for each of the 3 threats: immediate actions, numbered steps with
owner and time, and a 2-sentence summary for management.""",
    expected_output="Playbook for 3 threats",
    agent=response_agent,
    context=[triage_task, investigation_task]
)

# ---------------- RUN ----------------
crew = Crew(
    agents=[triage_agent, investigation_agent, response_agent],
    tasks=[triage_task, investigation_task, response_task],
    verbose=True
)

result = crew.kickoff()

with open("data/day10_report.txt", "w", encoding="utf-8") as f:
    f.write(str(result))

print("\nReport saved to data/day10_report.txt")