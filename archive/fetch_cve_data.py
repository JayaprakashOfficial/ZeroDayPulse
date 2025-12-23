import json
import pandas as pd
import requests

print("🌐 Fetching CVE data from NVD...")
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {"resultsPerPage": 2000}

response = requests.get(url, params=params, timeout=30)
data = response.json()

rows = []
for item in data.get("vulnerabilities", []):
    cve = item["cve"]
    desc = cve["descriptions"][0]["value"]
    metrics = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
    if metrics:
        rows.append({
            "CVE_ID": cve["id"],
            "Description": desc,
            "Attack_Vector": metrics.get("attackVector", "NETWORK"),
            "Attack_Complexity": metrics.get("attackComplexity", "LOW"),
            "Privileges_Required": metrics.get("privilegesRequired", "NONE"),
            "Base_Score": metrics.get("baseScore", 0.0)
        })

df = pd.DataFrame(rows)
df.to_csv("cve_training_data.csv", index=False)
print(f"✅ Saved {len(df)} CVEs to cve_training_data.csv")
