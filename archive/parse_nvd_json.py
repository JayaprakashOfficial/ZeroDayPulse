import requests
import pandas as pd
import time

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_cve_data(year):
    print(f"Fetching CVE data for {year} from NVD API...")
    results = []
    start_index = 0

    while True:
        params = {
            "pubStartDate": f"{year}-01-01T00:00:00.000",
            "pubEndDate": f"{year}-12-31T23:59:59.000",
            "resultsPerPage": 2000,
            "startIndex": start_index
        }

        response = requests.get(API_URL, params=params)
        if response.status_code != 200:
            print(f"❌ Error {response.status_code}")
            break

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break

        for v in vulnerabilities:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            if cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]

            severity = cvss.get("baseSeverity", "UNKNOWN") if cvss else "UNKNOWN"
            score = cvss.get("baseScore", 0) if cvss else 0
            vector = cvss.get("attackVector", "N/A") if cvss else "N/A"
            complexity = cvss.get("attackComplexity", "N/A") if cvss else "N/A"
            privilege = cvss.get("privilegesRequired", "N/A") if cvss else "N/A"

            results.append({
                "CVE_ID": cve_id,
                "Description": desc,
                "Severity": severity,
                "Impact_Score": score,
                "Attack_Vector": vector,
                "Attack_Complexity": complexity,
                "Privileges_Required": privilege
            })

        print(f"Fetched {len(results)} CVEs so far...")
        start_index += 2000
        time.sleep(1)

    return pd.DataFrame(results)

if __name__ == "__main__":
    import datetime

    end = datetime.datetime.utcnow()
    start = end - datetime.timedelta(days=90)  # last 3 months

    print(f"Fetching CVEs from {start.date()} to {end.date()}")
    API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_recent_cves():
        results = []
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT23:59:59.000"),
            "resultsPerPage": 2000
        }

        response = requests.get(API_URL, params=params)
        if response.status_code != 200:
            print(f"❌ Error {response.status_code}")
            return pd.DataFrame()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        for v in vulnerabilities:
            cve = v.get("cve", {})
            cve_id = cve.get("id", "")
            desc = ""
            if cve.get("descriptions"):
                desc = cve["descriptions"][0].get("value", "")

            metrics = cve.get("metrics", {})
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]

            severity = cvss.get("baseSeverity", "UNKNOWN") if cvss else "UNKNOWN"
            score = cvss.get("baseScore", 0) if cvss else 0
            vector = cvss.get("attackVector", "N/A") if cvss else "N/A"
            complexity = cvss.get("attackComplexity", "N/A") if cvss else "N/A"
            privilege = cvss.get("privilegesRequired", "N/A") if cvss else "N/A"

            results.append({
                "CVE_ID": cve_id,
                "Description": desc,
                "Severity": severity,
                "Impact_Score": score,
                "Attack_Vector": vector,
                "Attack_Complexity": complexity,
                "Privileges_Required": privilege
            })

        return pd.DataFrame(results)

    df = fetch_recent_cves()
    df.to_csv("nvd_recent.csv", index=False)
    print(f"✅ Saved {len(df)} CVEs to nvd_recent.csv")

