import streamlit as st
import pandas as pd

st.set_page_config (page_title= "AI Cybersecurity Risk Auditor", layout= "wide", initial_sidebar_state="expanded")
    
## Demo Data Temporary
findings = [{"id" : "sec-001", "title" : "unsafe shell execution", "severity" : "HIGH!", "file" : "src/commands.py", "line": "12", "scanner": "Bandit", "evidence" : "subprocess.call (True)" },]
   

## Sidebar
with st.sidebar:
    st.title ("Risk Auditor")
    st.caption("AI powered security monitoring, analysis and reporting")
    st.divider()

    st.subheader("Repository")
    repository = st.text_input("Repository path", value= "", placeholder= "path/to/your/repository",)

    if st.button("▶ Scan repository", use_container_width=True):
        if repository.strip():
            st.info("Backend integration pending. This demo uses sample data.")
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




