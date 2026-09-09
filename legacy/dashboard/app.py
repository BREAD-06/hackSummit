# dashboard/app.py
# Insider Threat AI — Streamlit Dashboard
# Run from project root: streamlit run dashboard/app.py

import sys, os

# Ensure project root is on the path and is the working directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
os.chdir(PROJECT_ROOT)   # so all relative data paths work regardless of where streamlit is invoked

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from agents.monitoring_agent    import MonitoringAgent
from agents.analysis_agent      import AnalysisAgent
from agents.detection_agent     import DetectionAgent
from agents.verification_agent  import VerificationAgent
from agents.response_agent      import ResponseAgent
from agents.learning_agent      import LearningAgent

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Insider Threat AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* ── Global ── */
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.block-container { padding-top: 1.5rem; padding-bottom: 2rem; }

/* ── Sidebar ── */
[data-testid="stSidebar"] {
    background: linear-gradient(160deg, #0a0f1e 0%, #0f172a 60%, #1a1040 100%);
    border-right: 1px solid #1e293b;
}
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
[data-testid="stSidebar"] .stButton > button {
    background: linear-gradient(135deg, #6366f1, #8b5cf6) !important;
    border: none !important; color: white !important;
    font-weight: 700 !important; border-radius: 10px !important;
    transition: all 0.2s ease; box-shadow: 0 4px 15px rgba(99,102,241,0.4);
}
[data-testid="stSidebar"] .stButton > button:hover {
    transform: translateY(-2px); box-shadow: 0 6px 20px rgba(99,102,241,0.6);
}

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid #334155; border-radius: 12px;
    padding: 1.2rem 1.5rem; box-shadow: 0 4px 20px rgba(0,0,0,0.3);
}
[data-testid="stMetricLabel"] { color: #94a3b8 !important; font-size: 0.8rem; font-weight: 600; }
[data-testid="stMetricValue"] { color: #f1f5f9 !important; font-size: 1.8rem; font-weight: 800; }
[data-testid="stMetricDelta"] { font-size: 0.75rem; }

/* ── Section headers ── */
h2, h3 { color: #e2e8f0 !important; }

/* ── Download button ── */
.stDownloadButton > button {
    background: linear-gradient(135deg, #0f766e, #0d9488) !important;
    color: white !important; border: none !important;
    border-radius: 8px !important; font-weight: 600 !important;
}
</style>
""", unsafe_allow_html=True)

# ── Dataset registry ────────────────────────────────────────────────────────────
DATASETS = {
    "🔴  CERT r4.2-1 — Real Insider Cases": {
        "data_dir": "data/r4.2-1",
        "score_percentile": 20.0,
        "description": "30 real insider threat users from the CERT r4.2 benchmark. "
                       "Ground-truth malicious insiders — model should flag most of them.",
        "badge": "REAL DATA",
    },
    "💾  Data Exfiltration Scenario": {
        "data_dir": "data/test_scenarios/exfiltration",
        "score_percentile": 20.0,
        "description": "Synthetic: 5 insiders doing after-hours USB + mass file access + "
                       "suspicious URL visits. Classic data theft pattern.",
        "badge": "SYNTHETIC",
    },
    "📧  Email Leak Scenario": {
        "data_dir": "data/test_scenarios/email_leak",
        "score_percentile": 20.0,
        "description": "Synthetic: 5 insiders sending mass emails with large attachments at night. "
                       "Common data exfiltration via email pattern.",
        "badge": "SYNTHETIC",
    },
    "✅  Normal Behavior Baseline": {
        "data_dir": "data/test_scenarios/normal",
        "score_percentile": 20.0,
        "description": "Synthetic: 10 normal 9-to-5 employees. "
                       "Used to verify the model doesn't over-flag benign activity.",
        "badge": "SYNTHETIC",
    },
    "🧠  Full Training Set (r4.2)": {
        "data_dir": "data/cert_r4.2",
        "score_percentile": None,
        "description": "Full 32M-row CERT r4.2 training dataset with model's built-in threshold. "
                       "⚠️ Takes several minutes to load.",
        "badge": "LARGE",
    },
}

PLOT_THEME = dict(
    plot_bgcolor="#0f172a",
    paper_bgcolor="#1e293b",
    font=dict(color="#e2e8f0"),
    margin=dict(l=20, r=20, t=40, b=20),
)


# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="background:linear-gradient(135deg,#1e1b4b,#0f172a);
            border-radius:16px;padding:2rem 2.5rem;margin-bottom:1.5rem;
            border:1px solid #312e81;box-shadow:0 8px 32px rgba(99,102,241,0.2)">
  <h1 style="margin:0;color:#e2e8f0;font-size:2rem;font-weight:800">
    🛡️ Insider Threat Detection AI
  </h1>
  <p style="margin:0.5rem 0 0;color:#94a3b8;font-size:0.95rem">
    Multi-agent anomaly detection pipeline • Isolation Forest • CERT r4.2 dataset
  </p>
</div>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Pipeline Controls")
    st.divider()

    dataset_name = st.selectbox("📁 Select Test Dataset", list(DATASETS.keys()))
    selected     = DATASETS[dataset_name]

    ds_exists = os.path.exists(selected["data_dir"])
    if ds_exists:
        st.success(f"✅ Dataset ready: `{selected['data_dir']}`")
    else:
        st.error(f"⚠️ Not found: `{selected['data_dir']}`\nRun `python generate_test_data.py` first.")

    st.caption(selected["description"])
    st.divider()

    model_path = st.text_input("🤖 Model Path", value="models/isolation_forest.pkl")
    retrain    = st.checkbox("🔄 Retrain after run", value=False)

    st.divider()
    run_btn = st.button("▶ Run Detection Pipeline", type="primary", use_container_width=True,
                        disabled=not ds_exists)

    st.divider()
    st.markdown("### 📚 All Datasets")
    for dname, dinfo in DATASETS.items():
        available = os.path.exists(dinfo["data_dir"])
        icon = "✅" if available else "⚠️"
        badge_color = {"REAL DATA": "#ef4444", "SYNTHETIC": "#6366f1", "LARGE": "#f59e0b"}.get(dinfo["badge"], "#64748b")
        st.markdown(
            f"{icon} **{dinfo['badge']}** &nbsp; {dname.split('  ')[1]}",
            unsafe_allow_html=True,
        )

    st.divider()
    st.markdown(
        "<small style='color:#64748b'>API available at "
        "<code>http://localhost:8000/docs</code> when running the FastAPI backend.</small>",
        unsafe_allow_html=True,
    )

# ── Run pipeline ───────────────────────────────────────────────────────────────
if run_btn:
    # Always clear previous results so the run feels fresh every time
    for _key in ["result", "dataset_name", "data_dir"]:
        st.session_state.pop(_key, None)

    progress = st.progress(0, text="Initialising pipeline…")

    try:
        with st.status("🔍 Running AI Detection Pipeline", expanded=True) as _status:

            # ── Step 1: MonitoringAgent ────────────────────────────────────────
            st.write("📡 **MonitoringAgent** — loading activity logs from disk…")
            progress.progress(5, text="MonitoringAgent: reading CSV files…")
            raw_df = MonitoringAgent(data_dir=selected["data_dir"]).run()
            st.write(f"   ✅ Loaded **{len(raw_df):,}** raw log records.")
            progress.progress(25, text="MonitoringAgent: done.")

            # ── Step 2: AnalysisAgent ──────────────────────────────────────────
            st.write("🔬 **AnalysisAgent** — engineering per-user × hour features…")
            progress.progress(30, text="AnalysisAgent: feature engineering…")
            df_features = AnalysisAgent().run(raw_df)
            st.write(f"   ✅ Feature table: **{len(df_features):,}** rows × {df_features.shape[1]} columns.")
            progress.progress(50, text="AnalysisAgent: done.")

            # ── Step 3: DetectionAgent ─────────────────────────────────────────
            st.write("🤖 **DetectionAgent** — scoring with Isolation Forest…")
            progress.progress(55, text="DetectionAgent: running anomaly model…")
            df_scored = DetectionAgent(
                model_path=model_path,
                score_percentile=selected["score_percentile"],
            ).run(df_features)
            n_anom = int(df_scored["is_anomaly"].sum())
            st.write(f"   ✅ Flagged **{n_anom:,}** anomalous records.")
            progress.progress(70, text="DetectionAgent: done.")

            # ── Step 4: VerificationAgent ──────────────────────────────────────
            st.write("✅ **VerificationAgent** — applying rule-based threat checks…")
            progress.progress(75, text="VerificationAgent: applying rules…")
            df_verified = VerificationAgent().run(df_scored)
            n_confirmed = int(df_verified["confirmed_threat"].sum()) if "confirmed_threat" in df_verified.columns else 0
            st.write(f"   ✅ Confirmed **{n_confirmed:,}** threats after rule verification.")
            progress.progress(88, text="VerificationAgent: done.")

            # ── Step 5: ResponseAgent ──────────────────────────────────────────
            st.write("🚨 **ResponseAgent** — logging confirmed alerts…")
            progress.progress(92, text="ResponseAgent: writing alert log…")
            ResponseAgent().run(df_verified)
            st.write("   ✅ Alerts written to `data/alerts.jsonl`.")

            # ── Step 6: LearningAgent (optional) ──────────────────────────────
            if retrain:
                st.write("🔄 **LearningAgent** — retraining model on new data…")
                progress.progress(95, text="LearningAgent: retraining…")
                LearningAgent(model_path=model_path).run(df_features)
                st.write("   ✅ Model retrained and saved.")

            progress.progress(100, text="Pipeline complete!")
            _status.update(label="✅ Pipeline complete!", state="complete", expanded=False)

        # ── Cache results in session state ─────────────────────────────────────
        st.session_state["result"] = {
            "total":       len(df_features),
            "anomalies":   n_anom,
            "confirmed":   n_confirmed,
            "verified_df": df_verified,
        }
        st.session_state["dataset_name"] = dataset_name
        st.session_state["data_dir"]     = selected["data_dir"]
        st.success(f"✅ Pipeline complete — analysed **{len(df_features):,}** feature rows.")

    except Exception as exc:
        progress.empty()
        st.error(f"❌ Pipeline error: {exc}")
        st.stop()

# ── Results ────────────────────────────────────────────────────────────────────
if "result" in st.session_state:
    result   = st.session_state["result"]
    df_v     = result["verified_df"]
    ds_label = st.session_state.get("dataset_name", "Unknown").strip()

    # ── Section label ──────────────────────────────────────────────────────────
    st.markdown(f"### 📊 Results — {ds_label}")

    # ── KPI row ────────────────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("📋 Feature Rows", f"{result['total']:,}",
              help="Total unique user × hour combinations analysed")
    c2.metric("🚨 Anomalies Flagged", f"{result['anomalies']:,}",
              delta=f"{result['anomalies'] / result['total'] * 100:.1f}% of total")
    c3.metric("⚠️ Confirmed Threats", f"{result['confirmed']:,}",
              delta=f"{result['confirmed'] / max(result['anomalies'], 1) * 100:.0f}% confirmed")
    c4.metric("👤 Threat Users",
              f"{df_v['user'].nunique() if not df_v.empty else 0}",
              help="Unique users with at least one confirmed threat")

    st.divider()

    # ── No threats path ────────────────────────────────────────────────────────
    if df_v.empty or "confirmed_threat" not in df_v.columns or not df_v["confirmed_threat"].any():
        st.success("✅ No confirmed threats found in this dataset.")

    else:
        confirmed_df = df_v[df_v["confirmed_threat"]].copy()

        # ── Per-user summary table ─────────────────────────────────────────────
        st.subheader("🔴 High-Risk User Summary")
        agg = (
            confirmed_df
            .groupby("user")
            .agg(
                Threat_Windows   = ("confirmed_threat", "sum"),
                Avg_Score        = ("anomaly_score", "mean"),
                After_Hours      = ("is_after_hours", "sum"),
                USB_Events       = ("usb_connect", "sum"),
                File_Ops         = ("file_count", "sum"),
                Emails_Sent      = ("email_count", "sum"),
                HTTP_Requests    = ("http_count", "sum"),
            )
            .sort_values("Avg_Score")
            .reset_index()
        )
        agg["Risk"] = agg["Avg_Score"].apply(
            lambda s: "🔴 Critical" if s < -0.05 else ("🟠 High" if s < 0.02 else "🟡 Medium")
        )
        st.dataframe(agg, use_container_width=True, height=280)

        st.divider()

        # ── Charts row 1 ──────────────────────────────────────────────────────
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("🕐 Threat Activity by Hour")
            if "hour" in confirmed_df.columns:
                hourly = confirmed_df.groupby("hour").size().reset_index(name="count")
                fig = px.bar(
                    hourly, x="hour", y="count",
                    color="count", color_continuous_scale="Reds",
                    labels={"hour": "Hour of Day", "count": "Threat Events"},
                )
                fig.update_layout(**PLOT_THEME, coloraxis_showscale=False)
                fig.add_vrect(x0=-0.5, x1=6.5,  fillcolor="rgba(239,68,68,0.08)", line_width=0,
                              annotation_text="After Hours", annotation_font_color="#94a3b8")
                fig.add_vrect(x0=19.5, x1=23.5, fillcolor="rgba(239,68,68,0.08)", line_width=0)
                st.plotly_chart(fig, use_container_width=True)

        with col2:
            st.subheader("📊 Anomaly Score Distribution")
            if "anomaly_score" in df_v.columns:
                fig2 = px.histogram(
                    df_v, x="anomaly_score", nbins=40,
                    color="confirmed_threat",
                    barmode="overlay", opacity=0.8,
                    color_discrete_map={True: "#ef4444", False: "#6366f1"},
                    labels={"anomaly_score": "Anomaly Score (↓ = more suspicious)",
                            "confirmed_threat": "Confirmed"},
                )
                fig2.update_layout(**PLOT_THEME)
                st.plotly_chart(fig2, use_container_width=True)

        # ── Charts row 2 ──────────────────────────────────────────────────────
        col3, col4 = st.columns(2)

        with col3:
            st.subheader("🔌 USB Events per User")
            if "usb_connect" in confirmed_df.columns and confirmed_df["usb_connect"].sum() > 0:
                usb = (
                    confirmed_df.groupby("user")[["usb_connect", "usb_disconnect"]]
                    .sum().reset_index()
                    .sort_values("usb_connect", ascending=False).head(15)
                )
                fig3 = px.bar(
                    usb, x="user", y=["usb_connect", "usb_disconnect"],
                    barmode="group",
                    color_discrete_map={"usb_connect": "#f59e0b", "usb_disconnect": "#64748b"},
                    labels={"value": "Events", "variable": "Type"},
                )
                fig3.update_layout(**PLOT_THEME)
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No USB events in confirmed threats.")

        with col4:
            st.subheader("📧 Email Volume per User")
            if "email_count" in confirmed_df.columns and confirmed_df["email_count"].sum() > 0:
                email = (
                    confirmed_df.groupby("user")[["email_count", "email_size_total"]]
                    .sum().reset_index()
                    .sort_values("email_count", ascending=False).head(15)
                )
                fig4 = px.bar(
                    email, x="user", y="email_count",
                    color="email_size_total", color_continuous_scale="OrRd",
                    labels={"email_count": "Emails Sent",
                            "email_size_total": "Total Size (bytes)"},
                )
                fig4.update_layout(**PLOT_THEME)
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("No email events in confirmed threats.")

        # ── Chart 5: File & HTTP (full width) ─────────────────────────────────
        st.subheader("📂 File & Web Activity per User (Flagged Records)")
        if "file_count" in confirmed_df.columns:
            act = (
                confirmed_df.groupby("user")[["file_count", "http_count"]]
                .sum().reset_index()
                .sort_values("file_count", ascending=False).head(20)
            )
            fig5 = px.bar(
                act, x="user", y=["file_count", "http_count"],
                barmode="group",
                color_discrete_map={"file_count": "#3b82f6", "http_count": "#8b5cf6"},
                labels={"value": "Count", "variable": "Activity"},
            )
            fig5.update_layout(**PLOT_THEME)
            st.plotly_chart(fig5, use_container_width=True)

        # ── Fired rules breakdown ──────────────────────────────────────────────
        rule_cols = [c for c in confirmed_df.columns if c.startswith("rule_")]
        if rule_cols:
            st.subheader("📌 Triggered Alert Rules")
            rule_counts = confirmed_df[rule_cols].sum().sort_values(ascending=False)
            rule_counts.index = [r.replace("rule_", "").replace("_", " ").title() for r in rule_counts.index]
            fig6 = px.bar(
                x=rule_counts.index, y=rule_counts.values,
                color=rule_counts.values, color_continuous_scale="Reds",
                labels={"x": "Rule", "y": "Times Fired"},
            )
            fig6.update_layout(**PLOT_THEME, coloraxis_showscale=False)
            st.plotly_chart(fig6, use_container_width=True)

        st.divider()

        # ── Full threat table ──────────────────────────────────────────────────
        st.subheader("📋 Confirmed Threat Records — Full Detail")
        display_cols = [c for c in confirmed_df.columns
                        if not c.startswith("rule_") or "confirmed_threat" in c]
        st.dataframe(confirmed_df[display_cols], use_container_width=True, height=350)

        # ── Download button ────────────────────────────────────────────────────
        csv = confirmed_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Results as CSV",
            data=csv,
            file_name=f"threats_{ds_label[:20].strip().replace(' ', '_')}.csv",
            mime="text/csv",
        )

# ── Landing state ──────────────────────────────────────────────────────────────
else:
    col_l, col_r = st.columns(2)

    with col_l:
        st.markdown("""
<div style="background:#1e293b;border-radius:12px;padding:1.5rem;border:1px solid #334155">
<h3 style="color:#e2e8f0;margin-top:0">🧠 How It Works</h3>

| Step | Agent | Action |
|------|-------|--------|
| 1 | MonitoringAgent | Loads CERT CSV logs (auto-detects format) |
| 2 | AnalysisAgent | Engineers per-user × hour features |
| 3 | DetectionAgent | Isolation Forest scores each row |
| 4 | VerificationAgent | Rule-based threat confirmation |
| 5 | ResponseAgent | Logs confirmed alerts |
</div>
""", unsafe_allow_html=True)

    with col_r:
        st.markdown("""
<div style="background:#1e293b;border-radius:12px;padding:1.5rem;border:1px solid #334155">
<h3 style="color:#e2e8f0;margin-top:0">📁 Available Test Datasets</h3>

| Dataset | Type | Threats? |
|---------|------|----------|
| CERT r4.2-1 | Real | ✅ Yes (30 insiders) |
| Data Exfiltration | Synthetic | ✅ Yes (USB + files) |
| Email Leak | Synthetic | ✅ Yes (mass email) |
| Normal Baseline | Synthetic | ❌ Should be none |
| Full r4.2 | Real (large) | ✅ Yes (3K+) |

> First time? Run `python generate_test_data.py` from the project root.
</div>
""", unsafe_allow_html=True)

    st.info("👈 Pick a dataset in the sidebar and click **▶ Run Detection Pipeline** to begin.")
