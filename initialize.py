"""Initialize configuration only. No sample firewall evidence or agent reviews."""
import json
from pathlib import Path
root = Path(__file__).resolve().parent
data = root / "data"
data.mkdir(exist_ok=True)
session = data / "session.json"
if not session.exists():
    session.write_text(json.dumps({
        "title": "Palis", "scope": "Local Windows Firewall", "mode": "Read-only collection",
        "agents": [
            {"id": "investigator", "name": "Exception Investigator", "role": "Intent and ownership"},
            {"id": "dependency", "name": "Dependency Analyst", "role": "Scope and application dependencies"},
            {"id": "challenger", "name": "Independent Challenger", "role": "Evidence quality and change review"}
        ],
        "limits": ["No synthetic evidence", "Human approval and UAC required for changes", "Specialists run separately"],
        "productDescription": "Firewall intelligence"
    }, indent=2), encoding="utf-8")
print("Configuration ready. Run python server.py to collect actual local evidence.")
