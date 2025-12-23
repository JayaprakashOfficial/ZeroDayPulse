import pandas as pd
import joblib
import requests

# ---------------------------------------
# 1. Fetch sample CVE data dynamically from NVD API
# ---------------------------------------
print("🌐 Fetching latest CVE data from NVD API...")
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {"resultsPerPage": 100}
response = requests.get(url, params=params, timeout=20)
data = response.json()

cve_list = []
for item in data.get('vulnerabilities', []):
    cve = item['cve']
    desc = cve['descriptions'][0]['value']
    metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {})

    cve_list.append({
        "CVE_ID": cve['id'],
        "Description": desc,
        "Attack_Vector": metrics.get("attackVector", "NETWORK"),
        "Attack_Complexity": metrics.get("attackComplexity", "LOW"),
        "Privileges_Required": metrics.get("privilegesRequired", "NONE")
    })

df = pd.DataFrame(cve_list)

print(f"✅ Retrieved {len(df)} CVEs for schema extraction.")

# ---------------------------------------
# 2. Extract categorical columns dynamically
# ---------------------------------------
cat_features = ['Attack_Vector', 'Attack_Complexity', 'Privileges_Required']
cat_input = pd.get_dummies(df[cat_features])

# Save detected categorical column names
cat_columns = list(cat_input.columns)
print(f"🧩 Extracted {len(cat_columns)} categorical columns from live data.")

# ---------------------------------------
# 3. Align with your trained model
# ---------------------------------------
try:
    model = joblib.load("rf_model.pkl")
    tfidf = joblib.load("tfidf_vectorizer.pkl")

    n_text_features = tfidf.transform(["test"]).shape[1]
    n_model_features = model.n_features_in_
    n_expected_cat = n_model_features - n_text_features

    if len(cat_columns) != n_expected_cat:
        print(f"⚠ Warning: Model expects {n_expected_cat} categorical features, "
              f"but live data provides {len(cat_columns)}.")
    else:
        print("✅ Model feature alignment verified.")
except Exception as e:
    print(f"⚠ Could not verify model alignment: {e}")

# ---------------------------------------
# 4. Save final categorical column schema
# ---------------------------------------
joblib.dump(cat_columns, "cat_columns.pkl")
print("💾 Saved categorical columns to cat_columns.pkl")
