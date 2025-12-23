#!/bin/bash

echo "🚀 ZeroDayPulse – Real-Time CVE Fetch + Dashboard Starting..."

# --- Activate venv ---
if [ -d "venv" ]; then
  source venv/bin/activate
else
  echo "⚠️  Virtual environment not found! Please create one using 'python3 -m venv venv'"
  exit 1
fi

# --- Ensure dependencies ---
pip install -q streamlit pandas numpy joblib plotly requests tqdm scikit-learn

echo ""
echo "⏱️  Select CVE fetch window:"
echo "   1️⃣  Last 1 Hour"
echo "   2️⃣  Last 1 Day"
echo "   3️⃣  Last 7 Days"
read -p "👉 Enter your choice (1/2/3): " choice

# --- Validate choice ---
if [[ "$choice" == "1" ]]; then
  TIME_WINDOW="hour"
elif [[ "$choice" == "2" ]]; then
  TIME_WINDOW="day"
elif [[ "$choice" == "3" ]]; then
  TIME_WINDOW="week"
else
  echo "⚠️ Invalid choice. Please choose 1, 2, or 3 only."
  exit 1
fi

# --- Python fetch + predict ---
python3 - <<PYCODE
import requests, json, subprocess
from datetime import datetime, timedelta

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
time_window = "${TIME_WINDOW}"

now = datetime.utcnow()
if time_window == "hour":
    start = now - timedelta(hours=1)
elif time_window == "day":
    start = now - timedelta(days=1)
else:
    start = now - timedelta(days=7)

start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

print(f"\n🕒 Fetching CVEs {start_str} → {now_str}")
print("📡 Contacting NVD API...")

try:
    params = {"resultsPerPage": 2000, "pubStartDate": start_str, "pubEndDate": now_str}
    response = requests.get(NVD_URL, params=params, timeout=60)
    response.raise_for_status()
    data = response.json()
    vulns = data.get("vulnerabilities", [])
    print(f"✅ {len(vulns)} CVEs fetched from NVD.")
    with open("latest_cve.json", "w") as f:
        json.dump(data, f, indent=2)
    print("💾 Saved to latest_cve.json")

    if vulns:
        print("🧩 Running prediction model...")
        subprocess.run(["python3", "sync_predictions.py"], check=True)
    else:
        print("⚠️ No CVEs found for this period.")
except Exception as e:
    print(f"❌ Error during fetch: {e}")
    exit(1)
PYCODE

# --- Launch Streamlit dashboard ---
echo ""
echo "🌐 Launching ZeroDayPulse Dashboard..."
echo "💡 Access it at: http://localhost:8501"
echo "🧩 Press CTRL + C to stop the dashboard."
streamlit run app.py --server.port 8501
