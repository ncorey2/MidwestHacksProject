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
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

st.set_page_config(page_title="AI Cybersecurity Risk Auditor", layout="wide", initial_sidebar_state="expanded")

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
        identity = {
            "scanner": finding.get("scanner", ""),
            "rule": finding.get("_rule", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line"),
            "title": finding.get("title", ""),
        }
        encoded = json.dumps(identity, sort_keys=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    current = {fingerprint(f): f for f in findings}
    previous = {}
    if history:
        previous = {fingerprint(f): f for f in history[-1].get("findings", [])}

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


# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.title("Risk Auditor")
    st.caption("AI powered security monitoring, analysis and reporting")
    st.divider()

    st.subheader("Repository")
    repository = st.text_input(
        "GitHub Repository",
        placeholder="owner/repo-name",
    )

    github_token = os.getenv("GITHUB_TOKEN", "")

    if st.button("▶ Scan repository", width="stretch"):
        if not repository.strip():
            st.error("Please enter a GitHub repository (e.g. owner/repo-name)")
        elif not github_token:
            st.error("GITHUB_TOKEN not found in .env")
        else:
            with st.spinner("Triggering GitHub Actions scan..."):
                trigger_url = f"https://api.github.com/repos/{repository.strip()}/actions/workflows/workflow.yml/dispatches"
                trigger_response = requests.post(
                    trigger_url,
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github+json",
                    },
                    json={"ref": "main"},
                    timeout=15,
                )

            if trigger_response.status_code == 204:
                st.success("Scan triggered on GitHub Actions!")
                st.info("Waiting for results... this may take 2-3 minutes.")

                with st.spinner("Waiting for scan to complete..."):
                    import time
                    run_id = None
                    time.sleep(5)

                    runs_url = f"https://api.github.com/repos/{repository.strip()}/actions/workflows/workflow.yml/runs"
                    runs_response = requests.get(
                        runs_url,
                        headers={
                            "Authorization": f"Bearer {github_token}",
                            "Accept": "application/vnd.github+json",
                        },
                        timeout=15,
                    )

                    if runs_response.status_code == 200:
                        runs = runs_response.json().get("workflow_runs", [])
                        if runs:
                            run_id = runs[0]["id"]

                    if run_id:
                        for _ in range(30):
                            time.sleep(10)
                            status_url = f"https://api.github.com/repos/{repository.strip()}/actions/runs/{run_id}"
                            status_response = requests.get(
                                status_url,
                                headers={
                                    "Authorization": f"Bearer {github_token}",
                                    "Accept": "application/vnd.github+json",
                                },
                                timeout=15,
                            )
                            status_data = status_response.json()
                            run_status = status_data.get("status")
                            conclusion = status_data.get("conclusion")

                            if run_status == "completed":
                                if conclusion in ("success", "failure"):
                                    st.success("Scan complete! Downloading results...")

                                    artifacts_url = f"https://api.github.com/repos/{repository.strip()}/actions/runs/{run_id}/artifacts"
                                    artifacts_response = requests.get(
                                        artifacts_url,
                                        headers={
                                            "Authorization": f"Bearer {github_token}",
                                            "Accept": "application/vnd.github+json",
                                        },
                                        timeout=15,
                                    )

                                    artifacts = artifacts_response.json().get("artifacts", [])
                                    reports_dir = os.path.join(BACKEND_DIR, "..", "reports")
                                    os.makedirs(reports_dir, exist_ok=True)

                                    for artifact in artifacts:
                                        download_url = artifact["archive_download_url"]
                                        artifact_name = artifact["name"]

                                        dl = requests.get(
                                            download_url,
                                            headers={"Authorization": f"Bearer {github_token}"},
                                            timeout=60,
                                        )

                                        zip_path = os.path.join(reports_dir, f"{artifact_name}.zip")
                                        with open(zip_path, "wb") as zf:
                                            zf.write(dl.content)

                                        import zipfile
                                        with zipfile.ZipFile(zip_path, "r") as z:
                                            z.extractall(reports_dir)
                                        os.remove(zip_path)

                                    st.success("Reports downloaded! Running AI analysis...")

                                    result = subprocess.run(
                                        [sys.executable, SCANNER_SCRIPT],
                                        cwd=BACKEND_DIR,
                                        capture_output=True,
                                        text=True,
                                        timeout=900,
                                    )

                                    if result.returncode == 0:
                                        response = requests.get(API_URL, timeout=10)
                                        findings = response.json()
                                        record = save_scan_history(findings)
                                        st.session_state.last_scan = record["timestamp"]
                                        st.success(f"Done! {len(findings)} findings loaded.")
                                        st.rerun()
                                    else:
                                        st.error("AI analysis failed.")
                                        st.code(result.stderr[-3000:])
                                break
                        else:
                            st.warning("Scan still running — check back in a moment.")

            elif trigger_response.status_code == 404:
                st.error("Repository or workflow not found. Check the repo name and that workflow.yml exists.")
            elif trigger_response.status_code == 401:
                st.error("Invalid GITHUB_TOKEN. Check your .env file.")
            else:
                st.error(f"Failed to trigger scan: {trigger_response.status_code}")

    # Navigation — always visible, always outside the button block
    st.divider()
    st.subheader("Navigation")
    page = st.radio(
        "Choose a view",
        ["Overview", "Security Findings", "Scan History"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("Prototype • Local-first security analysis")


# ── MAIN HEADER ───────────────────────────────────────────────────────────────
st.title("Security Overview")
st.write("Monitor vulnerabilities, understand risk, analyze risks and prioritize remediation across codebase.")
st.caption("Live findings from local analysis pipeline")

# ── SUMMARY METRICS ───────────────────────────────────────────────────────────
total = len(findings)
critical = sum(f["severity"].lower().startswith("critical") for f in findings)
high = sum(f["severity"].lower().startswith("high") for f in findings)
medium_low = sum(f["severity"].lower().startswith(("medium", "low")) for f in findings)

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Findings", total)
c2.metric("Critical", critical)
c3.metric("High Risk", high)
c4.metric("Medium / Low", medium_low)

st.divider()


# ── PAGES ─────────────────────────────────────────────────────────────────────
if page == "Overview":
    left, right = st.columns([3, 2])

    with left:
        st.subheader("Most recent security findings")
        for finding in findings[:4]:
            with st.container(border=True):
                col1, col2 = st.columns([4, 1])
                col1.markdown(f"**{finding['title']}**")
                col1.caption(f"{finding['id']} · {finding['file']} · {finding['scanner']}")
                col2.write(finding["severity"])

    with right:
        st.subheader("AI risk assessment")
        if findings:
            top = findings[0]
            with st.container(border=True):
                st.markdown("**Highest-priority Issue**")
                st.write(top["title"])
                st.caption(f"{top['id']} · {top['severity']}")
                st.write(top.get("reasoning", "No reasoning available."))

    st.subheader("Finding Distribution")
    distribution = pd.DataFrame({
        "Severity": ["Critical", "High", "Medium", "Low"],
        "Count": [
            sum(f["severity"].lower().startswith("critical") for f in findings),
            sum(f["severity"].lower().startswith("high") for f in findings),
            sum(f["severity"].lower().startswith("medium") for f in findings),
            sum(f["severity"].lower().startswith("low") for f in findings),
        ]
    })

    severity_colors = {
        "Critical": "#DC2626",
        "High": "#EF4444",
        "Medium": "#FACC15",
        "Low": "#22C55E",
    }

    fig = px.bar(
        distribution,
        x="Count",
        y="Severity",
        orientation="h",
        color="Severity",
        color_discrete_map=severity_colors,
        category_orders={"Severity": ["Critical", "High", "Medium", "Low"]},
        text="Count",
    )
    fig.update_layout(
        xaxis_title="Count",
        yaxis_title="Severity",
        showlegend=False,
        template="plotly_dark",
        yaxis={"categoryorder": "array", "categoryarray": ["Low", "Medium", "High", "Critical"]},
        margin=dict(l=20, r=20, t=20, b=20),
    )
    fig.update_traces(textposition="outside")
    st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})


elif page == "Security Findings":
    st.subheader("All security findings")
    st.caption("Review, filter, and inspect detected security issues.")

    def normalize_severity(value):
        return value.strip().upper().rstrip("!.,:").title()

    severity_options = ["Critical", "High", "Medium", "Low"]
    scanner_options = sorted({f["scanner"] for f in findings})

    col1, col2 = st.columns(2)
    with col1:
        selected_severities = st.multiselect("Filter by severity", severity_options, default=severity_options)
    with col2:
        selected_scanners = st.multiselect("Filter by scanner", scanner_options, default=scanner_options)

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
                "ID": f["id"],
            }
            for f in filtered
        ]
        st.dataframe(display_findings, width="stretch", hide_index=True)

        selected_id = st.selectbox(
            "Inspect a finding",
            [f["id"] for f in filtered],
            format_func=lambda fid: next(f["title"] for f in filtered if f["id"] == fid),
        )

        selected = next(f for f in filtered if f["id"] == selected_id)
        severity = normalize_severity(selected["severity"])

        severity_icons = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

        with st.container(border=True):
            st.markdown(f"### {selected['title']}")
            st.write(f"**Severity:** {severity_icons.get(severity, '⚪')} {severity}")
            st.write(f"**Finding ID:** `{selected['id']}`")
            st.write(f"**File:** `{selected['file']}`")
            st.write(f"**Line:** {selected['line']}")
            st.write(f"**Scanner:** {selected['scanner']}")

            st.write("**Evidence**")
            st.code(selected.get("evidence", "No evidence provided."))

            st.divider()

            st.write("**AI Risk Analysis**")
            st.write(selected.get("reasoning", "No AI reasoning is available for this finding."))

            if selected.get("owasp_category"):
                st.divider()
                col1, col2 = st.columns(2)
                with col1:
                    st.write("**OWASP Category**")
                    st.info(selected["owasp_category"])
                with col2:
                    st.write("**NIST Control**")
                    st.info(selected.get("nist_control", "N/A"))

            if selected.get("solution"):
                st.write("**Recommended Solution**")
                st.success(selected["solution"])

            if selected.get("occurrences") is not None:
                st.write(f"**Occurrences:** {selected['occurrences']}")

            st.write("**Suggested Next Step**")
            if "shell" in selected["title"].lower():
                st.write(
                    "Avoid shell execution when possible. Prefer passing commands as "
                    "argument lists, validate inputs, and review whether shell access is necessary."
                )
            else:
                st.write("Review the affected code, verify the finding, and apply an appropriate fix.")

    else:
        st.success("No findings match your selected filters.")


elif page == "Scan History":
    st.subheader("Scan History")
    st.caption("A record of every scan run against your repository.")

    history = load_scan_history()

    if not history:
        st.info("No scan history yet. Run a scan from the sidebar to get started.")
    else:
        summary_rows = [
            {
                "Scan ID": record.get("scan_id", "—"),
                "Timestamp": record.get("timestamp", "—"),
                "Status": record.get("status", "—"),
                "Total Findings": record.get("total_findings", 0),
                "New": record.get("new_count", 0),
                "Resolved": record.get("resolved_count", 0),
                "Unchanged": record.get("unchanged_count", 0),
            }
            for record in reversed(history)
        ]
        st.dataframe(summary_rows, width="stretch", hide_index=True)

        if len(history) > 1:
            st.subheader("Risk Trend")
            trend_df = pd.DataFrame([
                {
                    "Scan": record.get("scan_id", ""),
                    "Total": record.get("total_findings", 0),
                    "New": record.get("new_count", 0),
                    "Resolved": record.get("resolved_count", 0),
                }
                for record in history
            ])
            fig = px.line(
                trend_df,
                x="Scan",
                y=["Total", "New", "Resolved"],
                markers=True,
                template="plotly_dark",
                color_discrete_map={"Total": "#60A5FA", "New": "#EF4444", "Resolved": "#22C55E"},
            )
            fig.update_layout(
                xaxis_title="Scan",
                yaxis_title="Findings",
                margin=dict(l=20, r=20, t=20, b=20),
            )
            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

        st.subheader("Inspect a Scan")
        scan_ids = [r.get("scan_id") for r in reversed(history)]
        selected_scan_id = st.selectbox("Select scan", scan_ids)
        selected_record = next(r for r in history if r.get("scan_id") == selected_scan_id)

        col1, col2, col3 = st.columns(3)
        col1.metric("Total", selected_record.get("total_findings", 0))
        col2.metric("New", selected_record.get("new_count", 0))
        col3.metric("Resolved", selected_record.get("resolved_count", 0))

        if selected_record.get("new_findings"):
            with st.expander(f"🔴 New findings ({selected_record['new_count']})"):
                for f in selected_record["new_findings"]:
                    st.write(f"**{f['title']}** — `{f['file']}` line {f['line']}")

        if selected_record.get("resolved_findings"):
            with st.expander(f"✅ Resolved findings ({selected_record['resolved_count']})"):
                for f in selected_record["resolved_findings"]:
                    st.write(f"**{f['title']}** — `{f['file']}` line {f['line']}")

st.divider()
st.caption("AI Cybersecurity Risk Auditor · Prototype")