import streamlit as st
import pandas as pd
import plotly.express as px
import requests
import os
import sys
import subprocess
import json
import hashlib
from datetime import datetime

st.set_page_config (page_title= "AI Cybersecurity Risk Auditor", layout= "wide", initial_sidebar_state="expanded")

API_URL = "http://127.0.0.1:5001/api/results"

try:
    response = requests.get(API_URL, timeout=10)
    response.raise_for_status()
    findings = response.json()

    if not isinstance(findings, list):
        st.error("The API returned an unexpected data format.")
        st.stop()

except requests.RequestException as e:
    st.error(f"Could not load security findings: {e}")
    st.info("Make sure your Flask server is running on port 5001.")
    st.stop()

BACKEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "Backend")
)
SCANNER_SCRIPT = os.path.join(BACKEND_DIR, "test.py")
HISTORY_FILE = os.path.join(BACKEND_DIR, "scan_history.json")


def load_scan_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            history = json.load(file)

        return history if isinstance(history, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_scan_history(findings):
    history = load_scan_history()

    def fingerprint(finding):
        # Prefer the scanner's rule ID when available.
        identity = {
            "scanner": finding.get("scanner", ""),
            "rule": finding.get("_rule", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line"),
            "title": finding.get("title", ""),
        }
        encoded = json.dumps(identity, sort_keys=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    current = {
        fingerprint(finding): finding
        for finding in findings
    }

    previous = {}
    if history:
        previous = {
            fingerprint(finding): finding
            for finding in history[-1].get("findings", [])
        }

    new_ids = current.keys() - previous.keys()
    resolved_ids = previous.keys() - current.keys()
    unchanged_ids = current.keys() & previous.keys()

    record = {
        "scan_id": f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "status": "Complete",
        "total_findings": len(findings),
        "new_count": len(new_ids),
        "resolved_count": len(resolved_ids),
        "unchanged_count": len(unchanged_ids),
        "new_findings": [current[key] for key in new_ids],
        "resolved_findings": [previous[key] for key in resolved_ids],
        "findings": findings,
    }

    history.append(record)

    with open(HISTORY_FILE, "w", encoding="utf-8") as file:
        json.dump(history, file, indent=2)

    return record



if "scan_status" not in st.session_state:
    st.session_state.scan_status = "Not scanned"

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None

   

## Sidebar
with st.sidebar:
    st.title ("Risk Auditor")
    st.caption("AI powered security monitoring, analysis and reporting")
    st.divider()

    st.subheader("Repository")
    repository = st.text_input("Repository path", value= "", placeholder= "path/to/your/repository",)

    if st.button("▶ Scan repository", width="stretch"):
        st.session_state.scan_status = "Scanning"

        try:
            with st.spinner(
                "Processing security reports and generating AI analysis..."
            ):
                result = subprocess.run(
                    [sys.executable, SCANNER_SCRIPT],
                    cwd=BACKEND_DIR,
                    capture_output=True,
                    text=True,
                    timeout=900
                )

            if result.returncode != 0:
                st.session_state.scan_status = "Scan failed"
                st.error("The scanner pipeline failed.")

                if result.stderr:
                    st.code(result.stderr[-5000:])

            else:
                
                # Fetch the newly generated findings from Flask
                response = requests.get(API_URL, timeout=10)
                response.raise_for_status()
                findings = response.json()

                st.session_state.scan_status = "Complete"
                record = save_scan_history(findings)

                st.session_state.last_scan = record["timestamp"]

                st.success(
                    f"Pipeline complete! Loaded {len(findings)} findings."
                )

                st.write(
                    f"New: {record['new_count']} · "
                    f"Resolved: {record['resolved_count']} · "
                    f"Unchanged: {record['unchanged_count']}"
                )
                
                with st.expander("View pipeline logs"):
                    st.text(result.stdout[-10000:] or "No output.")

        except subprocess.TimeoutExpired:
            st.session_state.scan_status = "Timed out"
            st.error(
                "The pipeline exceeded 15 minutes. "
                "Check the backend terminal and Ollama."
            )

        except (requests.RequestException, ValueError) as e:
            st.session_state.scan_status = "Error"
            st.error(f"Could not reload findings: {e}")


    st.divider()
    st.subheader("Navigation")
    page = st.radio(
        "Choose a view",
        ["Overview", "Security Findings", "Scan History"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Prototype • Local-first security analysis")

## Main Header Bar
st.title("Security Overview")
st.write( "Monitor vulnerabilities, understand risk, analysize risks and prioritze remediation across codebase.")
st.caption("Live findings from local analysis pipeline")

## Summary Card

total = len(findings)
critical = sum(f["severity"] == "Critical" for f in findings)
high = sum(f["severity"] == "High" for f in findings)
medium_low = sum(f["severity"] in ("Medium", "Low") for f in findings)

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Findings", total)
c2.metric("Critical", critical)
c3.metric("High Risk", high)
c4.metric("Medium / Low", medium_low)

st.divider()

## Navigation
if page == "Overview":
    left, right = st.columns([3,2])
    with left :
        st.subheader("Most recent security findings")
        for finding in findings[:4]:
            with st.container(border=True):
                col1, col2 = st.columns([4,1])
                col1.markdown(f"**{finding['title']}**")
                col1.caption(f"{finding['id']} . {finding['file']} . f{finding['scanner']}")
                col2.write(finding["severity"])

    with right:
        st.subheader("AI risk assessment")
        with st.container(border=True):
            st.markdown("Highest-priority Issue")
            st.write("Hardcoded secret detected")
            st.caption("sec-001 . Critical")
            st.write("Demo recommendation : verify credentials are exposed, remove them from source code and rotate any compromised secrets.")
            st.info("AI analysis sample content")

    st.subheader("Finding Distribution")
    distribution = pd.DataFrame({
    "Severity": ["Critical", "High", "Medium", "Low"],
    "Count": [
        sum(f["severity"].lower().startswith("critical") for f in findings),
        sum(f["severity"].lower().startswith("high") for f in findings),
        sum(f["severity"].lower().startswith("medium") for f in findings),
        sum(f["severity"].lower().startswith("low") for f in findings)
    ]
})

    severity_colors = {
        "Critical": "#DC2626",
        "High": "#EF4444",
        "Medium": "#FACC15",
        "Low": "#22C55E"
    }

    fig = px.bar(
        distribution,
        x="Count",
        y="Severity",
        orientation="h",
        color="Severity",
        color_discrete_map=severity_colors,
        category_orders={
            "Severity": ["Critical", "High", "Medium", "Low"]
        },
    text="Count"
    )

    fig.update_layout(
    xaxis_title="Count",
    yaxis_title="Severity",
    showlegend=False,
    template="plotly_dark",
    yaxis={"categoryorder": "array",
           "categoryarray": ["Low", "Medium", "High", "Critical"]},
    margin=dict(l=20, r=20, t=20, b=20)
    )

    fig.update_traces(textposition="outside")

    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

elif page == "Security Findings" :
    st.subheader("All security findings")
    st.caption("Review, filter, and inspect detected security issues.")
    severity_options = ["Critical", "High", "Medium", "Low"]
    
    def normalize_severity(value):
        value = value.strip().upper().rstrip("!.,:")
        return value.title()

    scanner_options = sorted({f["scanner"] for f in findings})

    col1, col2 = st.columns(2)

    with col1:
        selected_severities = st.multiselect(
            "Filter by severity",
            severity_options,
            default=severity_options
        )

    with col2:
        selected_scanners = st.multiselect(
            "Filter by scanner",
            scanner_options,
            default=scanner_options
        )

    filtered = [
        f for f in findings
        if normalize_severity(f["severity"]) in selected_severities
        and f["scanner"] in selected_scanners
    ]

    st.write(f"**{len(filtered)} finding(s) shown**")

    if filtered:
        display_findings = [
            {
                "Severity": normalize_severity(f["severity"]),
                "Title": f["title"],
                "File": f["file"],
                "Line": f["line"],
                "Scanner": f["scanner"],
                "ID": f["id"]
            }
            for f in filtered
        ]

        st.dataframe(
            display_findings,
            width="stretch",
            hide_index=True
        )

        selected_id = st.selectbox(
            "Inspect a finding",
            [f["id"] for f in filtered],
            format_func=lambda finding_id: next(
                f["title"] for f in filtered
                if f["id"] == finding_id
            )
        )

        selected = next(
            f for f in filtered if f["id"] == selected_id
        )

        severity = normalize_severity(selected["severity"])

        severity_colors = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢"
        }

        with st.container(border=True):
            st.markdown(f"### {selected['title']}")

            st.write(
                f"**Severity:** {severity_colors.get(severity, '⚪')} "
                f"{severity}"
            )
            st.write(f"**Finding ID:** `{selected['id']}`")
            st.write(f"**File:** `{selected['file']}`")
            st.write(f"**Line:** {selected['line']}")
            st.write(f"**Scanner:** {selected['scanner']}")

            st.write("**Evidence**")
            st.code(selected.get("evidence", "No evidence provided."))

            st.divider()

            st.write("**AI Risk Analysis**")
            st.write(
                selected.get(
                "reasoning",
                "No AI reasoning is available for this finding."
            )
        )

            if selected.get("occurrences") is not None:
                st.write(
                f"**Occurrences:** {selected['occurrences']}"
            )

            st.write("**Suggested Next Step — Sample Guidance**")
            if "shell" in selected["title"].lower():
                st.write(
                    "Avoid shell execution when possible. Prefer "
                    "passing commands as argument lists, validate "
                    "inputs, and review whether shell access is necessary."
                )
            else:
                st.write(
                    "Review the affected code, verify the finding, "
                    "and apply an appropriate fix."
                )

    else:
        st.success("No findings match your selected filters.")


elif page == "Scan History":
    st.subheader("Scan History")
    st.write("Historical scan records will appear here after backend integration.")

    st.dataframe([{
                "Scan": "DEMO-003",
                "Date": "Sample",
                "Trigger": "Scheduled",
                "Findings": 5,
                "Status": "Demo",
            },
            {
                "Scan": "DEMO-002",
                "Date": "Sample",
                "Trigger": "Manual",
                "Findings": 3,
                "Status": "Demo",
            },
        ],
        width="stretch",
        hide_index=True,
    )

st.divider()
st.caption(
    "AI Cybersecurity Risk Auditor · Prototype · "
)
