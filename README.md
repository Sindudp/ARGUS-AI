ARGUS-AI

Autonomous Response and Guardian for Unified Security A multi-agent AI system that detects, investigates and responds to simulated cyber threats.

MCA project, Siddaganga Institute of Technology (SIT), Tumakuru. Author: Sindu D P

All data in this project is simulated and runs on a local machine. The system is defensive only.

What it does

Security teams receive far more alerts than analysts can read. ARGUS-AI automates the first steps:

Detect - an Isolation Forest model scores every log event from 0 to 100.
Triage - an AI agent classifies each group of events, rates its severity and maps it to a MITRE ATT&CK technique.
Investigate - an AI agent calls two tools on its own: a CVE search (RAG over ChromaDB) and a MITRE ATT&CK lookup.
Respond - an AI agent writes a short containment playbook with owners and times.
Show - a FastAPI backend and a React dashboard display alerts, statistics and the latest AI report.


Architecture

Simulated logs (data/log_generator.py)
        |
        v
Isolation Forest (tools/anomaly_detector.py)  -> severity score 0-100 per event
        |
        v  events grouped, labels hidden from the agents
Triage Agent  ->  Investigation Agent  ->  Response Agent        (CrewAI + Groq LLM)
                     |        |
                     |        +-- MITRE ATT&CK lookup tool (tools/mitre_tool.py)
                     +----------- CVE search tool (ChromaDB + MiniLM embeddings)
        |
        v
data/latest_report.json  ->  FastAPI (main.py)  ->  React dashboard


Tech stack

Python 3.11, CrewAI, Groq (openai/gpt-oss-120b), scikit-learn (Isolation Forest), ChromaDB, sentence-transformers (all-MiniLM-L6-v2), FastAPI, React, Recharts, Axios, NVD CVE data.

Project structure

agents/    argus_pipeline.py (full pipeline), triage_agent.py, investigation_agent.py, response_agent.py
tools/     anomaly_detector.py, threat_intel_tool.py, mitre_tool.py, log_summary.py, evaluate.py, groq_patch.py
rag/       embedder.py, vector_store.py, cve_loader.py, nvd_loader.py
data/      log_generator.py, sample_logs.json, nvd_cache.json
dashboard/ React app (src/App.js, src/ReportPanel.js)
main.py    FastAPI backend
Setup
bash
git clone https://github.com/Sindudp/ARGUS-AI.git
cd ARGUS-AI
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

Create a .env file in the project root (never commit it):

GROQ_API_KEY=your_key_here
MODEL_NAME=openai/gpt-oss-120b

Load the CVE knowledge base (uses the cached NVD data, so no internet is needed):

bash
python rag/nvd_loader.py
Run
bash
python data/log_generator.py        # create simulated attack logs
python agents/argus_pipeline.py     # run ML + the three agents, saves data/latest_report.json
python tools/evaluate.py            # evaluate the ML detector on a held-out test set

uvicorn main:app --reload --port 8000     # API at http://127.0.0.1:8000/docs
cd dashboard && npm install && npm start  # dashboard at http://localhost:3000

Click Simulate Attack on the dashboard, then Load Latest Report at the bottom of the page.

Screenshots
Dashboard	AI investigation report
Dashboard	AI report
ML evaluation	Pipeline run
Evaluation	Pipeline
Results

ML detector on a held-out synthetic test set (420 events: 300 normal, 120 attacks):

Method	Precision	Recall	F1
Isolation Forest (ARGUS-AI)	1.00	0.975	0.987
Fixed-threshold rule	1.00	1.00	1.00

Recall per attack type: brute force 1.0, data exfiltration 1.0, port scan 1.0, ransomware 0.9.

The attacks in the simulator are far from normal traffic, so a simple threshold rule does as well. The advantage of Isolation Forest is that it needs no hand-written thresholds. Real traffic (for example CICIDS2017) would be a harder and fairer test.

Limitations
All logs and the ML training data are synthetic. Results are indicative only.
The knowledge base holds 20 CVEs. A CVE match is a text-similarity candidate, not proof that the flaw was exploited.
The MITRE ATT&CK table covers 8 techniques. Detection and mitigation text is a simplified summary.
The LLM agents give different wording on every run and sometimes state an inference as fact, so an analyst must review the output.
The agents can miss links between groups (for example a shared external IP).
The free Groq tier has a 8,000 tokens-per-minute limit, so runs take a few minutes.
The ML model uses five event features. A successful login after many failures, and web-exploit attempts, are not visible to it. The agents and the CVE tool cover those cases.
The API has no authentication. It is meant for local use.
Future work

Evaluate on CICIDS2017, load a larger CVE set from the NVD feed, use the full MITRE ATT&CK dataset, add live updates with WebSocket, and add human approval before any response action.