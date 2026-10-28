"""Streamlit analytics dashboard over investigation data (pandas + plotly).

Run:  streamlit run analytics/dashboard.py
"""
from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from memory import InvestigationMemory

st.set_page_config(page_title="Aegis-SOC Analytics", layout="wide")
st.title("🛡️ Aegis-SOC — Security Analytics Dashboard")

data = InvestigationMemory().all()
if not data:
    st.info("No investigations yet. Run one via the API: POST /investigate")
    st.stop()

rows = []
for inv in data:
    for f in inv.get("findings", []):
        rows.append({"investigation": inv["id"], "scanner": f["scanner"],
                     "severity": f["severity"], "cve": f.get("cve_id"),
                     "cvss": f.get("cvss_score")})
df = pd.DataFrame(rows)
if df.empty:
    st.info("Investigations exist but contain no findings. Check the API log (scan.done lines) for scanner errors.")
    st.stop()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Investigations", len(data))
c2.metric("Total findings", len(df))
c3.metric("Critical", int((df.severity == "CRITICAL").sum()))
c4.metric("Avg CVSS", round(df.cvss.dropna().mean(), 1) if df.cvss.notna().any() else 0)

left, right = st.columns(2)
with left:
    st.subheader("Findings by severity")
    sev = df.severity.value_counts().reset_index()
    sev.columns = ["severity", "count"]
    st.plotly_chart(px.bar(sev, x="severity", y="count", color="severity"),
                    use_container_width=True)
with right:
    st.subheader("Findings by scanner")
    sc = df.scanner.value_counts().reset_index()
    sc.columns = ["scanner", "count"]
    st.plotly_chart(px.pie(sc, names="scanner", values="count"),
                    use_container_width=True)

st.subheader("All findings")
st.dataframe(df, use_container_width=True)
