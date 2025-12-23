import subprocess

def explain_cve(cve_id, description, attack_vector, impact_score, severity):
    prompt = f"""
You are a cybersecurity analyst.

Explain the following vulnerability clearly.

CVE ID: {cve_id}
Description: {description}
Attack Vector: {attack_vector}
Impact Score: {impact_score}
Predicted Severity: {severity}

Explain:
1. What this vulnerability does
2. Why it is dangerous
3. Suggested mitigation
"""

    result = subprocess.run(
        ["ollama", "run", "mistral"],
        input=prompt,
        text=True,
        capture_output=True
    )

    return result.stdout

