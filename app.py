# app.py
import streamlit as st
import pandas as pd
import plotly.express as px
import numpy as np
import os
import joblib
import json
from llm_explainer import explain_cve
from datetime import datetime
from io import StringIO
import subprocess

# -----------------------------
# Page Config
# -----------------------------
st.set_page_config(
    page_title="ZeroDayPulse – AI Vulnerability Prediction Dashboard",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -----------------------------
# Custom Theme & Header
# -----------------------------
st.markdown("""
<style>
    .main {
        background-color: #f5f6fa;
    }
    h1, h2, h3, h4 {
        color: #512da8;
        font-family: 'Poppins', sans-serif;
    }
    div[data-testid="stMetricValue"] {
        color: #2e7d32;
        font-size: 30px;
        font-weight: bold;
    }
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

st.title("🧠 ZeroDayPulse – AI-Based Real-Time Vulnerability Prediction System")
st.caption("🚨 Real-time CVE Severity Prediction | Sourced from NVD | Built with Streamlit, Plotly, and AI")

# -----------------------------
# Helper: load artifacts safely
# -----------------------------
@st.cache_data(ttl=600)
def load_artifacts_safe():
    artifacts = {}
    try:
        artifacts['model'] = joblib.load("rf_model.pkl")
    except Exception as e:
        artifacts['model'] = None
        artifacts['model_err'] = str(e)
    try:
        artifacts['tfidf'] = joblib.load("tfidf_vectorizer.pkl")
    except Exception as e:
        artifacts['tfidf'] = None
        artifacts['tfidf_err'] = str(e)
    try:
        artifacts['cat_columns'] = joblib.load("cat_columns.pkl")
    except Exception as e:
        artifacts['cat_columns'] = None
        artifacts['cat_columns_err'] = str(e)
    return artifacts

art = load_artifacts_safe()
model = art.get('model')
tfidf = art.get('tfidf')
cat_columns = art.get('cat_columns')

if model is None:
    st.error("Model artifact 'rf_model.pkl' not found or failed to load. Check the project folder.")
if tfidf is None:
    st.error("TF-IDF artifact 'tfidf_vectorizer.pkl' not found or failed to load.")
if cat_columns is None:
    st.warning("Categorical columns 'cat_columns.pkl' not found. Some automatic alignment will still attempt to run.")

# -----------------------------
# Utility: compute predictions from latest_cve.json
# -----------------------------
def load_latest_cve_json(path="latest_cve.json"):
    if not os.path.exists(path):
        st.error(f"File not found: {path}. Run your fetch script (run.sh / sync_predictions) first.")
        return pd.DataFrame()
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception as e:
        st.error(f"Failed to read {path}: {e}")
        return pd.DataFrame()

    rows = []
    for item in data.get("vulnerabilities", []):
        try:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descs = cve.get("descriptions", [])
            desc = descs[0].get("value", "") if descs else ""
            cvss = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
            rows.append({
                "CVE_ID": cve_id,
                "Description": desc,
                "Impact_Score": cvss.get("baseScore", 0.0),
                "Attack_Vector": cvss.get("attackVector", "NETWORK"),
                "Attack_Complexity": cvss.get("attackComplexity", "LOW"),
                "Privileges_Required": cvss.get("privilegesRequired", "NONE")
            })
        except Exception:
            continue
    return pd.DataFrame(rows)

def predict_from_cve_dataframe(df, threshold=0.5):
    if model is None or tfidf is None:
        st.error("Model or TF-IDF missing — cannot predict.")
        return df
    if df.empty:
        return df

    X_text = tfidf.transform(df['Description'].fillna(''))
    X_text_array = X_text.toarray()

    cat_features = ['Attack_Vector', 'Attack_Complexity', 'Privileges_Required']
    for f in cat_features:
        if f not in df.columns:
            df[f] = "N/A"
    cat_input = pd.get_dummies(df[cat_features])

    if cat_columns:
        for col in cat_columns:
            if col not in cat_input.columns:
                cat_input[col] = 0
        extra_cols = [c for c in cat_input.columns if c not in cat_columns]
        if extra_cols:
            cat_input.drop(columns=extra_cols, inplace=True)
        cat_input = cat_input.reindex(columns=cat_columns, fill_value=0)

    try:
        X_input = np.hstack((X_text_array, cat_input.values))
    except Exception as e:
        st.error(f"Failed to combine TF-IDF and categorical features: {e}")
        return df

    if hasattr(model, "n_features_in_"):
        expected = model.n_features_in_
        actual = X_input.shape[1]
        if actual != expected:
            if actual < expected:
                pad = np.zeros((X_input.shape[0], expected - actual))
                X_input = np.hstack([X_input, pad])
            else:
                X_input = X_input[:, :expected]

    probabilities = model.predict_proba(X_input)[:, 1]
    labels = (probabilities > threshold).astype(int)

    df = df.copy()
    df['Probability_HighCritical'] = probabilities
    df['Predicted_Label'] = labels
    df['Predicted_Severity'] = df['Predicted_Label'].apply(lambda x: "HIGH/CRITICAL" if x == 1 else "LOW/MEDIUM")

    return df

# -----------------------------
# Sidebar Controls
# -----------------------------
st.sidebar.header("Data Source & Controls")
data_source = st.sidebar.radio("Load predictions from:", ("latest_pred.csv (synced)", "Recompute from latest_cve.json"))
threshold = st.sidebar.slider("Prediction threshold", 0.0, 1.0, 0.5, 0.01)
recompute_pressed = st.sidebar.button("Recompute predictions (from latest_cve.json)")

df = pd.DataFrame()

if data_source == "latest_pred.csv (synced)":
    if os.path.exists("latest_pred.csv"):
        try:
            # Use 'python' engine for better error handling, skip malformed lines
            df = pd.read_csv("latest_pred.csv", on_bad_lines="skip", engine="python", encoding="utf-8")
        except Exception as e:
            st.warning(f"⚠️ Could not read latest_pred.csv properly: {e}")
            df = pd.DataFrame()
        
        # Validate essential columns
        if 'Probability_HighCritical' not in df.columns or 'Predicted_Severity' not in df.columns:
            st.warning("⚠️ Missing required prediction columns. Recomputing...")
            df = pd.DataFrame()
    
    # If file empty or recompute requested, generate predictions
    if df.empty and recompute_pressed:
        df_json = load_latest_cve_json()
        df = predict_from_cve_dataframe(df_json, threshold=threshold)

elif data_source == "Recompute from latest_cve.json":
    df_json = load_latest_cve_json()
    if recompute_pressed:
        df = predict_from_cve_dataframe(df_json, threshold=threshold)
    elif os.path.exists("latest_pred.csv"):
        try:
            df = pd.read_csv("latest_pred.csv", on_bad_lines="skip", engine="python", encoding="utf-8")
        except Exception as e:
            st.warning(f"⚠️ Error reading backup latest_pred.csv: {e}")
            df = pd.DataFrame()

if df.empty:
    st.warning("No prediction data available. Either run run.sh or press 'Recompute predictions'.")
    st.stop()

# -----------------------------
# Sidebar Filters
# -----------------------------
st.sidebar.header("🔍 Filter Options")
st.sidebar.markdown("Refine CVE data for precise analysis.")

df["Attack_Vector"] = df["Attack_Vector"].astype(str).fillna("Unknown")
df["Privileges_Required"] = df["Privileges_Required"].astype(str).fillna("Unknown")
df["Attack_Complexity"] = df["Attack_Complexity"].astype(str).fillna("Unknown")
df["Predicted_Severity"] = df["Predicted_Severity"].astype(str).fillna("LOW/MEDIUM")

severity_options = st.sidebar.multiselect("Severity Level", ["HIGH/CRITICAL", "LOW/MEDIUM"], default=["HIGH/CRITICAL", "LOW/MEDIUM"])
attack_vector_filter = st.sidebar.multiselect("Attack Vector", sorted(df["Attack_Vector"].unique().tolist()))
privileges_filter = st.sidebar.multiselect("Privileges Required", sorted(df["Privileges_Required"].unique().tolist()))
keyword = st.sidebar.text_input("🔎 Search Keyword (CVE ID or Description)")
prob_range = st.sidebar.slider("Probability Range", 0.0, 1.0, (0.0, 1.0))

filtered_df = df.copy()
if severity_options:
    filtered_df = filtered_df[filtered_df["Predicted_Severity"].isin(severity_options)]
if attack_vector_filter:
    filtered_df = filtered_df[filtered_df["Attack_Vector"].isin(attack_vector_filter)]
if privileges_filter:
    filtered_df = filtered_df[filtered_df["Privileges_Required"].isin(privileges_filter)]
if keyword:
    filtered_df = filtered_df[filtered_df["CVE_ID"].str.contains(keyword, case=False) |
                              filtered_df["Description"].str.contains(keyword, case=False)]
filtered_df = filtered_df[(filtered_df["Probability_HighCritical"] >= prob_range[0]) &
                          (filtered_df["Probability_HighCritical"] <= prob_range[1])]

# -----------------------------
# KPI Section
# -----------------------------
st.markdown("## 📊 Real-Time Dashboard KPIs")
col1, col2, col3 = st.columns(3)
col1.metric("Total CVEs", len(filtered_df))
col2.metric("High / Critical CVEs", len(filtered_df[filtered_df["Predicted_Severity"] == "HIGH/CRITICAL"]))
col3.metric("Low / Medium CVEs", len(filtered_df[filtered_df["Predicted_Severity"] == "LOW/MEDIUM"]))

# -----------------------------
# Data Table
# -----------------------------
with st.expander("📋 View Detailed CVE Data", expanded=False):
    st.dataframe(
        filtered_df.style.apply(
            lambda row: ["background-color: #ffcdd2" if row["Predicted_Severity"] == "HIGH/CRITICAL" else "" for _ in row],
            axis=1,
        ),
        use_container_width=True,
    )

# -----------------------------

st.markdown("## 🧠 AI-Powered CVE Explanation")

# Use the same dataset shown in KPIs and charts
if filtered_df.empty:
    st.info("No CVEs available for AI explanation.")
else:
    selected_cve_id = st.selectbox(
        "Select a CVE from the dashboard",
        filtered_df["CVE_ID"].tolist()
    )

    selected_row = filtered_df[filtered_df["CVE_ID"] == selected_cve_id].iloc[0]

    if st.button("🔍 AI Explain & Mitigate"):
        with st.spinner("Analyzing selected CVE using GenAI..."):
            try:
                explanation = explain_cve(
                    selected_row["CVE_ID"],
                    selected_row["Description"],
                    selected_row["Attack_Vector"],
                    selected_row["Impact_Score"],
                    selected_row["Predicted_Severity"]
                )
                st.markdown(explanation)
            except Exception:
                st.error("⚠️ GenAI service is temporarily unavailable.")

# Visualization
# -----------------------------
st.markdown("## 📈 Vulnerability Analytics")
tab1, tab2, tab3 = st.tabs(["📊 Bar Chart", "🥧 Pie Chart", "📅 Trend View"])

with tab1:
    fig_bar = px.bar(
        filtered_df.head(30),
        x="CVE_ID",
        y="Probability_HighCritical",
        color="Predicted_Severity",
        color_discrete_map={"HIGH/CRITICAL": "#d32f2f", "LOW/MEDIUM": "#388e3c"},
        hover_data=["Description", "Impact_Score"],
        title="Top 30 CVEs by Predicted Probability",
    )
    fig_bar.update_layout(height=500)
    st.plotly_chart(fig_bar, use_container_width=True)

with tab2:
    pie_data = filtered_df["Predicted_Severity"].value_counts()
    fig_pie = px.pie(
        names=pie_data.index,
        values=pie_data.values,
        color=pie_data.index,
        color_discrete_map={"HIGH/CRITICAL": "#e53935", "LOW/MEDIUM": "#43a047"},
        hole=0.4,
    )
    st.plotly_chart(fig_pie, use_container_width=True)

with tab3:
    trend_data = filtered_df.groupby(["Attack_Vector", "Predicted_Severity"]).size().reset_index(name="Count")
    fig_trend = px.bar(
        trend_data,
        x="Attack_Vector",
        y="Count",
        color="Predicted_Severity",
        barmode="group",
        color_discrete_map={"HIGH/CRITICAL": "#c62828", "LOW/MEDIUM": "#66bb6a"},
        title="Vulnerabilities by Attack Vector and Severity"
    )
    st.plotly_chart(fig_trend, use_container_width=True)

# -----------------------------
# Download Section
# -----------------------------
st.markdown("## 💾 Export Data")
csv_buffer = StringIO()
filtered_df.to_csv(csv_buffer, index=False)
st.download_button(
    "📥 Download Filtered CVE Report",
    data=csv_buffer.getvalue(),
    file_name=f"CVE_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv"
)

# -----------------------------
# Footer
# -----------------------------
st.markdown("""
---
✅ **LIVE Data Feed Enabled**
🧩 Developed by DOT | © 2025 ZeroDayPulse
""")
