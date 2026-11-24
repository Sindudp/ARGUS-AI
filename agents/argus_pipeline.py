# agents/argus_pipeline.py
# Purpose: the full ARGUS-AI pipeline
#   logs -> Isolation Forest scores -> Triage -> Investigation (CVE + MITRE tools) -> Response
# The final report is saved to data/latest_report.json and shown on the dashboard.

import os
import sys
import json
from dotenv import load_dotenv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ROOT)

import tools.groq_patch  # fixes the Groq + CrewAI cache_breakpoint error

from crewai import Agent, Task, Crew, LLM
from tools.threat_intel_tool import search_cve_database
from tools.mitre_tool import lookup_mitre_technique
from tools.anomaly_detector import ARGUSAnomalyDetector
from tools.log_summary import summarize_logs, task_text, save_report

load_dotenv()

MODEL_NAME = os.getenv("MODEL_NAME", "openai/gpt-oss-120b")
llm = LLM(
    model=f"groq/{MODEL_NAME}",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0.2
)

# ---------------- LOAD LOGS AND RUN THE ML MODEL ----------------
log_path = os.path.join(ROOT, "data", "generated_logs.json")
if not os.path.exists(log_path):
    print("Run python data/log_generator.py first!")
    sys.exit()

with open(log_path, encoding="utf-8") as f:
    raw_logs = json.load(f)

detector = ARGUSAnomalyDetector()
detector.train()
summary = summarize_logs(raw_logs, detector)
print(f"Raw events: {len(raw_logs)} -> {len(summary)} groups (every event scored by the ML model)")

# ---------------- AGENTS ----------------
triage_agent = Agent(
    role="ARGUS Triage Specialist",
    goal="Classify security events and score their severity from 0 to 100",
    backstory="You are a SOC analyst with 15 years of experience. "
              "You classify attacks from the evidence and assign MITRE ATT&CK technique IDs.",
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
    max_iter=12
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
    description=f"""Here are grouped security events. 'ml_max_severity' is the 0-100 score from the
Isolation Forest model and 'ml_anomalous_events' is how many events in the group it flagged.
{json.dumps(summary, indent=2)}

For each group give: what attack it most likely is (from the evidence), a final severity score
(0-100) that you justify using the ML score and the data, and the MITRE ATT&CK technique ID
(for example T1110). If a group is clearly malicious but the ML score is 0, say that the ML model
did not flag it.

RULES:
- Use only the fields shown. Do not assume a protocol, tool or product (for example SMB, RDP or Mimikatz) unless it appears in the data.
- If the data does not show which protocol was used, give the general technique ID (for example T1021) and not a sub-technique.
- Use 'source_scope' and 'dest_scope' exactly as given. Never call an internal address external.
- The ML score is only one input. Do not lower a rating just because the ML score is low when the evidence is clear (for example a very large transfer to an external address, or a process that is named as malicious).
- Link groups that share a source or destination IP and say so (for example a successful login from the same IP as a failed-login group means the account is Likely compromised, so rate that pair at least as high as the failed-login group).""",
    expected_output="A table of groups with attack type, final severity and MITRE technique ID, plus a short list of linked groups",
    agent=triage_agent
)

exploit_queries = "\n".join(
    f"- {g['group']}: use exactly this CVE search query: \"{g['description']}\""
    for g in summary if "description" in g
)

investigation_task = Task(
    description="""From the triage result pick the 4 MOST SEVERE distinct threats. Count linked groups as ONE threat (for example G1 and G2 together, or a chain on the same host). Also investigate any group that has a 'description' of an application exploit attempt, because only those can match a CVE.
For each threat:
1. Call 'CVE Intelligence Search' ONCE, describing the weakness an attacker would exploit. If the group has a 'description', use that description word for word as the search query. If it returns 'No strongly matching CVE found', do not search again for that threat.
2. Call 'MITRE ATT&CK Lookup' ONCE with the technique ID.
3. Write: attack chain, likely attacker type, possible related CVE (or 'No strongly matching CVE found'), and root cause. Keep each threat under 150 words.

STRICT RULES:
- Use only facts from the event summaries and tool results. Do not invent malware names, tools, protocols, patch numbers or products that are not in them.
- Only cite a CVE that a tool returned in this run, and only if its description matches the product or weakness in the evidence. Never cite a CVE from memory.
- Do not guess who the attacker is (for example state-sponsored or botnet) unless the data shows it. Write 'Cannot be determined from the logs'.
- A CVE is only a possible match from a text search. Never claim it was exploited.
- Use 'source_scope' and 'dest_scope' exactly as given. Never call an internal address external.
- When you describe HOW something happened and the logs do not show it directly, start the sentence with 'Likely:'."""
    + (("\n\nEXACT CVE SEARCH QUERIES:\n" + exploit_queries) if exploit_queries else ""),
    expected_output="Short investigation report for the selected threats that cites only CVE IDs returned by the tool, plus MITRE details",
    agent=investigation_agent,
    context=[triage_task]
)

response_task = Task(
    description="""Using the triage and investigation results, write a response
playbook for each investigated threat: a 2-sentence summary for management, 2 immediate actions, then AT MOST 6 numbered steps with owner and time. Keep every step under 20 words. Finish every playbook completely.

RULES:
- Base each playbook only on the triage and investigation results. Do not mention a CVE, malware name or product that does not appear in them. Describe how an attack happened only with the word 'Likely', unless the event summaries show it directly.
- Blocking at the perimeter firewall applies only to EXTERNAL addresses. For an INTERNAL source address, isolate or investigate that host instead.
- If the triage result links groups (for example failed logins followed by a successful login from the same IP), treat the later stage as having happened. Do not tell the team to 'verify whether' it happened; tell them to respond to it.""",
    expected_output="Playbook for each investigated threat",
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

report = save_report(
    os.path.join(ROOT, "data", "latest_report.json"),
    summary,
    task_text(triage_task),
    task_text(investigation_task),
    task_text(response_task) or str(result),
    MODEL_NAME,
)

with open(os.path.join(ROOT, "data", "latest_report.txt"), "w", encoding="utf-8") as f:
    f.write("TRIAGE\n" + report["triage"] + "\n\nINVESTIGATION\n" + report["investigation"]
            + "\n\nPLAYBOOKS\n" + report["playbooks"])

print("\nReport saved to data/latest_report.json (the dashboard reads this file)")
