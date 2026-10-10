import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config (page_title= "AI Cybersecurity Risk Auditor", layout= "wide", initial_sidebar_state="expanded")
    
if "scan_status" not in st.session_state:
    st.session_state.scan_status = "Not scanned"

if "last_scan" not in st.session_state:
    st.session_state.last_scan = None


## Demo Data Temporary
findings = [{"id" : "sec-001", "title" : "unsafe shell execution", "severity" : "High", "file" : "src/commands.py", "line": "12", "scanner": "Bandit", "evidence" : "subprocess.call (True)" },]
   

## Sidebar
with st.sidebar:
    st.title ("Risk Auditor")
    st.caption("AI powered security monitoring, analysis and reporting")
    st.divider()

    st.subheader("Repository")
    repository = st.text_input("Repository path", value= "", placeholder= "path/to/your/repository",)

    if st.button("▶ Scan repository", width="stretch"):
        if repository.strip():
            import time
            st.session_state.scan_status = "Scanning demo data..."
            with st.spinner("Simulating security scan..."):
                time.sleep(1.5)

            st.session_state.scan_status = "Demo scan complete"
            st.session_state.last_scan = time.strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            st.success(
                "Demo scan complete! No real repository scan was performed."
            )
        else:
            st.warning("Enter a repository path first.")


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
st.caption("DEMO DATA")

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

            st.write("**AI Explanation — Sample**")
            st.info(
                "This finding may indicate a security risk. "
                "Review the scanner evidence and the surrounding code "
                "before determining its actual impact."
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
    "Scanner and AI results are not connected yet"
)
