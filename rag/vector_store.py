# rag/vector_store.py
# Purpose: Store CVE vulnerability data in ChromaDB
# so ARGUS can search by meaning during investigation

import chromadb
from chromadb.config import Settings
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rag.embedder import ARGUSEmbedder

class ARGUSVectorStore:
    def __init__(self):
        print("🔧 ARGUS Vector Store: Initializing ChromaDB...")
        
        # Create ChromaDB client — stores data locally on your laptop
        self.client = chromadb.PersistentClient(
            path="./data/chromadb"  # saves database in data folder
        )
        
        # Create or get collection — like a table in a database
        self.collection = self.client.get_or_create_collection(
            name="cve_vulnerabilities",
            metadata={"description": "CVE vulnerability data for ARGUS-AI"}
        )
        
        # Initialize embedder for converting text to vectors
        self.embedder = ARGUSEmbedder()
        
        print(" ARGUS Vector Store: Ready!")
        print(f"Current CVEs stored: {self.collection.count()}")

    def add_cves(self, cve_list):
        # cve_list = list of dicts with id, description, severity
        print(f"\n📥 Adding {len(cve_list)} CVEs to ChromaDB...")
        
        documents = []   # text descriptions
        embeddings = []  # vector numbers
        ids = []         # unique IDs
        metadatas = []   # extra info
        
        for cve in cve_list:
            documents.append(cve['description'])
            embeddings.append(self.embedder.embed(cve['description']))
            ids.append(cve['id'])
            metadatas.append({
                "severity": cve.get('severity', 'UNKNOWN'),
                "cvss_score": str(cve.get('cvss_score', '0.0'))
            })
        
        # Add everything to ChromaDB at once
        self.collection.add(
            documents=documents,
            embeddings=embeddings,
            ids=ids,
            metadatas=metadatas
        )
        
        print(f" Successfully added {len(cve_list)} CVEs!")
        print(f" Total CVEs in database: {self.collection.count()}")

    def search(self, query, n_results=3):
        # Search ChromaDB for CVEs similar to the query
        print(f"\n🔍 Searching for: '{query}'")
        
        # Convert query to vector
        query_embedding = self.embedder.embed(query)
        
        # Search ChromaDB
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results
        )
        
        # Format results nicely
        formatted = []
        for i in range(len(results['ids'][0])):
            formatted.append({
                "cve_id": results['ids'][0][i],
                "description": results['documents'][0][i],
                "severity": results['metadatas'][0][i]['severity'],
                "cvss_score": results['metadatas'][0][i]['cvss_score'],
                "distance": results['distances'][0][i]
            })
        
        return formatted

    def get_count(self):
        return self.collection.count()


# Test it directly
if __name__ == "__main__":
    store = ARGUSVectorStore()
    
    # Sample CVE data to test
    sample_cves = [
        {
            "id": "CVE-2023-44487",
            "description": "HTTP/2 Rapid Reset Attack allows remote attackers to cause denial of service via rapid stream resets. Affects web servers and causes massive CPU usage.",
            "severity": "HIGH",
            "cvss_score": "7.5"
        },
        {
            "id": "CVE-2023-23397",
            "description": "Microsoft Outlook privilege escalation vulnerability. Attacker sends specially crafted email to steal NTLM hashes without user interaction. Used in brute force and credential attacks.",
            "severity": "CRITICAL",
            "cvss_score": "9.8"
        },
        {
            "id": "CVE-2023-20198",
            "description": "Cisco IOS XE web UI privilege escalation. Allows unauthenticated remote attacker to create admin account. Used for unauthorized access and lateral movement.",
            "severity": "CRITICAL",
            "cvss_score": "10.0"
        },
        {
            "id": "CVE-2023-4966",
            "description": "Citrix Bleed vulnerability allows attackers to retrieve session tokens and bypass authentication. Used for data exfiltration and unauthorized access to sensitive systems.",
            "severity": "CRITICAL",
            "cvss_score": "9.4"
        },
        {
            "id": "CVE-2022-30190",
            "description": "Microsoft Windows Support Diagnostic Tool remote code execution via malicious Word documents. Used to deploy ransomware and malware on target systems.",
            "severity": "HIGH",
            "cvss_score": "7.8"
        }
    ]
    
    # Add CVEs to database
    store.add_cves(sample_cves)
    
    # Test search
    print("\n" + "="*50)
    print("ARGUS CVE SEARCH TEST")
    print("="*50)
    
    # Search 1 — brute force related
    results = store.search("brute force login attack failed password attempts")
    print("\n Search: 'brute force login attack'")
    for r in results:
        print(f"  → {r['cve_id']} | {r['severity']} | {r['description'][:60]}...")
    
    # Search 2 — data exfiltration
    results = store.search("data exfiltration unauthorized data transfer")
    print("\n Search: 'data exfiltration'")
    for r in results:
        print(f"  → {r['cve_id']} | {r['severity']} | {r['description'][:60]}...")
    
    print("\n Vector Store working!") 
