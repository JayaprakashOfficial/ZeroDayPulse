import requests
import pandas as pd
import numpy as np
import joblib
from datetime import datetime, timedelta

# -----------------------------
# 1. Load trained artifacts
# -----------------------------
model = joblib.load("rf_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")

# Expected feature size
expected_features = model.n_features_in_  # 5014

# -----------------------------
# 2. Fetch latest CVEs
# -----------------------------
print("Fetching latest CVEs from NVD API...")
end = datetime.utcnow()
start = end - timedelta(days=7)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
    "resultsPerPage": 2000
}

response = requests.get(API_URL, params=params)
data = response.json()

cve_list = []
for item in data.get("vulnerabilities", []):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    description = cve.get("descriptions", [{}])[0].get("value", "")
    metrics = cve.get("metrics", {})
    cvss = None
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
    impact_score = cvss.get("baseScore", 0) if cvss else 0
    attack_vector = cvss.get("attackVector", "N/A") if cvss else "N/A"
    attack_complexity = cvss.get("attackComplexity", "N/A") if cvss else "N/A"
    privileges_required = cvss.get("privilegesRequired", "N/A") if cvss else "N/A"

    cve_list.append({
        "CVE_ID": cve_id,
        "Description": description,
        "Impact_Score": impact_score,
        "Attack_Vector": attack_vector,
        "Attack_Complexity": attack_complexity,
        "Privileges_Required": privileges_required
    })

df = pd.DataFrame(cve_list)
print(f"✅ Fetched {len(df)} CVEs")

# -----------------------------
# 3. Prepare features
# -----------------------------
# TF-IDF transform
X_text = tfidf.transform(df['Description']).toarray()

# One-hot encode categorical
cat_cols = ['Attack_Vector','Attack_Complexity','Privileges_Required']
X_cat = pd.get_dummies(df[cat_cols])

# Align categorical columns
training_cat_cols = [
    'Attack_Complexity_HIGH','Attack_Complexity_LOW',
    'Attack_Vector_ADJACENT_NETWORK','Attack_Vector_LOCAL','Attack_Vector_NETWORK',
    'Privileges_Required_HIGH','Privileges_Required_LOW','Privileges_Required_NONE'
]
for col in training_cat_cols:
    if col not in X_cat.columns:
        X_cat[col] = 0
X_cat = X_cat[training_cat_cols]

# Combine features
X_input = np.hstack((X_text, X_cat.values))

# -----------------------------
# 3a. Pad if necessary
# -----------------------------
# This ensures X_input always matches model.n_features_in_
if X_input.shape[1] < expected_features:
    pad_width = expected_features - X_input.shape[1]
    X_input = np.hstack((X_input, np.zeros((X_input.shape[0], pad_width))))
elif X_input.shape[1] > expected_features:
    X_input = X_input[:, :expected_features]

# -----------------------------
# 4. Predict
# -----------------------------
predictions = model.predict(X_input)
probabilities = model.predict_proba(X_input)[:, 1]

df['Predicted_Severity'] = ["HIGH/CRITICAL" if p==1 else "LOW/MEDIUM" for p in predictions]
df['Probability_HighCritical'] = probabilities.round(2)

# -----------------------------
# 5. Save results
# -----------------------------
df.to_csv("nvd_realtime_predictions.csv", index=False)
print("✅ Saved predictions to nvd_realtime_predictions.csv")
print(df[['CVE_ID','Predicted_Severity','Probability_HighCritical']].head())
