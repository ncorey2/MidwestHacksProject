# run_once_seed_history.py  — place in your Backend folder and run it once
import json
from datetime import datetime, timedelta

base_time = datetime.now() - timedelta(hours=6)

history = [
    {
        "scan_id": "SCAN-20261010-140000",
        "timestamp": (base_time).isoformat(timespec="seconds"),
        "status": "Complete",
        "total_findings": 41,
        "new_count": 41,
        "resolved_count": 0,
        "unchanged_count": 0,
        "new_findings": [
            {"title": "Hardcoded AWS Secret Key", "file": "config/settings.py", "line": 12, "severity": "Critical", "scanner": "Semgrep", "id": "SEC-001"},
            {"title": "SQL Injection Risk", "file": "api/users.py", "line": 87, "severity": "High", "scanner": "Bandit", "id": "SEC-002"},
        ],
        "resolved_findings": [],
        "findings": []
    },
    {
        "scan_id": "SCAN-20261010-160000",
        "timestamp": (base_time + timedelta(hours=2)).isoformat(timespec="seconds"),
        "status": "Complete",
        "total_findings": 35,
        "new_count": 3,
        "resolved_count": 9,
        "unchanged_count": 32,
        "new_findings": [
            {"title": "Insecure Cookie Flag", "file": "auth/session.py", "line": 44, "severity": "Medium", "scanner": "Semgrep", "id": "SEC-012"},
        ],
        "resolved_findings": [
            {"title": "Hardcoded AWS Secret Key", "file": "config/settings.py", "line": 12, "severity": "Critical", "scanner": "Semgrep", "id": "SEC-001"},
        ],
        "findings": []
    },
    {
        "scan_id": "SCAN-20261010-180000",
        "timestamp": (base_time + timedelta(hours=4)).isoformat(timespec="seconds"),
        "status": "Complete",
        "total_findings": 28,
        "new_count": 1,
        "resolved_count": 8,
        "unchanged_count": 27,
        "new_findings": [
            {"title": "Weak Cipher Algorithm", "file": "utils/crypto.py", "line": 19, "severity": "High", "scanner": "Bandit", "id": "SEC-021"},
        ],
        "resolved_findings": [
            {"title": "SQL Injection Risk", "file": "api/users.py", "line": 87, "severity": "High", "scanner": "Bandit", "id": "SEC-002"},
        ],
        "findings": []
    },
]

with open("scan_history.json", "w") as f:
    json.dump(history, f, indent=2)

print("Done! scan_history.json created with 3 scan snapshots.")