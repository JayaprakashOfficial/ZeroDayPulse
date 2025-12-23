import pandas as pd
import json
import joblib
import numpy as np
from datetime import datetime

print("🧩 Loading model and vectorizer...")
try:
    model = joblib.load("rf_model.pkl")
    tfidf = joblib.load("tfidf_vectorizer.pkl")
    cat_columns = joblib.load("cat_columns.pkl")
except Exception as e:
    print(f"❌ Model/TF-IDF/Cat Columns load error: {e}")
    exit(1)

# --- Load CVE JSON ---
print("🕒 Reading CVE data from latest_cve.json...")
try:
    with open("latest_cve.json", "r") as f:
        data = json.load(f)
except Exception as e:
    print(f"❌ Error reading latest_cve.json: {e}")
    exit(1)

vulns = data.get("vulnerabilities", [])
print(f"📦 Total CVEs in JSON: {len(vulns)}")

if not vulns:
    print("⚠️ No CVEs found. Exiting.")
    exit(0)

# --- Extract CVE fields safely ---
rows = []
for v in vulns:
    try:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        desc = ""
        if "descriptions" in cve and len(cve["descriptions"]) > 0:
            desc = cve["descriptions"][0].get("value", "")

        # ✅ Handle CVSS 4.0 / 3.1 / 3.0 dynamically
        metrics_all = cve.get("metrics", {})
        metrics_data = {}

        if "cvssMetricV40" in metrics_all:
            metrics_data = metrics_all["cvssMetricV40"][0].get("cvssData", {})
        elif "cvssMetricV31" in metrics_all:
            metrics_data = metrics_all["cvssMetricV31"][0].get("cvssData", {})
        elif "cvssMetricV30" in metrics_all:
            metrics_data = metrics_all["cvssMetricV30"][0].get("cvssData", {})

        # Extract with defaults
        impact_score = metrics_data.get("baseScore", 0.0)
        attack_vector = metrics_data.get("attackVector", "NETWORK")
        attack_complexity = metrics_data.get("attackComplexity", "LOW")
        priv_req = metrics_data.get("privilegesRequired", "NONE")

        rows.append({
            "CVE_ID": cve_id,
            "Description": desc,
            "Impact_Score": impact_score,
            "Attack_Vector": attack_vector,
            "Attack_Complexity": attack_complexity,
            "Privileges_Required": priv_req,
            "Published_Date": cve.get("published", datetime.utcnow().isoformat())
        })

    except Exception as e:
        print(f"⚠️ Skipping CVE due to parse error: {e}")
        continue

df = pd.DataFrame(rows)
if df.empty:
    print("⚠️ No valid CVEs to process.")
    exit(0)

# Drop entries without a usable description
df.dropna(subset=["Description"], inplace=True)
print(f"📊 Processing {len(df)} CVEs...")

# --- Text vectorization ---
X_text = tfidf.transform(df["Description"].fillna("")).toarray()

# --- One-hot encode categorical features ---
cat_features = ["Attack_Vector", "Attack_Complexity", "Privileges_Required"]
cat_input = pd.get_dummies(df[cat_features])

# Align with training-time categorical columns
for col in cat_columns:
    if col not in cat_input.columns:
        cat_input[col] = 0
extra = [c for c in cat_input.columns if c not in cat_columns]
if extra:
    cat_input.drop(columns=extra, inplace=True)
cat_input = cat_input.reindex(columns=cat_columns, fill_value=0)

# --- Combine numeric + text features ---
X_combined = np.hstack((X_text, cat_input.values))

# --- Fix feature length mismatch ---
expected = getattr(model, "n_features_in_", X_combined.shape[1])
if X_combined.shape[1] != expected:
    diff = expected - X_combined.shape[1]
    if diff > 0:
        X_combined = np.hstack([X_combined, np.zeros((X_combined.shape[0], diff))])
    else:
        X_combined = X_combined[:, :expected]

# --- Predict ---
probs = model.predict_proba(X_combined)[:, 1]
labels = (probs > 0.45).astype(int)  # slightly lower threshold for sensitivity

df["Probability_HighCritical"] = probs
df["Predicted_Label"] = labels
df["Predicted_Severity"] = df["Predicted_Label"].apply(
    lambda x: "HIGH/CRITICAL" if x == 1 else "LOW/MEDIUM"
)
df["Fetched_Time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# --- Save results ---
df.to_csv("latest_pred.csv", index=False, lineterminator="\n", encoding="utf-8")
print(f"✅ Synced predictions saved: {len(df)} CVEs")
print(f"🔸 High/Critical: {len(df[df['Predicted_Severity']=='HIGH/CRITICAL'])}")
print(f"🟢 Low/Medium   : {len(df[df['Predicted_Severity']=='LOW/MEDIUM'])}")
print("🤖 Predictions updated successfully in latest_pred.csv")

