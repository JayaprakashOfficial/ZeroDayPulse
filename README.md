<p>
  <h1>🔐 ZeroDayPulse</h1>
  <p>
    <b>AI-Driven Zero-Day Vulnerability Prediction & Analysis Platform</b><br>
    Real-time CVE Severity Prediction • GenAI Explainability • Open-Source
  </p>
</p>

---

## 📘 Project Overview

**ZeroDayPulse** is an **AI-powered vulnerability intelligence platform** designed to **predict, analyze, and explain the severity of newly disclosed zero-day vulnerabilities in real time**.

The system leverages:
- Machine Learning models trained on historical **CVE data**
- Structured metadata from the **National Vulnerability Database (NVD)**
- **Open-source Generative AI (LLM)** for human-readable explanations

The interactive dashboard enables cybersecurity analysts to quickly identify high-risk vulnerabilities, understand attack characteristics, and prioritize remediation effectively.

---

## 📌 Problem Statement

Zero-day vulnerabilities pose a **critical threat** to organizations, as they are often exploited before patches are available. Traditional CVSS scoring methods rely heavily on manual analysis and may lag behind emerging attack trends.

**ZeroDayPulse addresses this challenge by automatically predicting the potential severity of newly reported vulnerabilities using AI**, enabling proactive defense and efficient threat prioritization.

---

## 🎯 Objectives

- 📥 Collect and preprocess real-world CVE data from NVD feeds  
- 🧠 Predict vulnerability severity using machine learning  
- 🔗 Combine textual descriptions with structured CVSS attributes  
- 📊 Provide real-time, interactive vulnerability analytics  
- 🗣️ Generate human-readable explanations using open-source GenAI  
- 🔌 Enable future integration with enterprise security tools  

---

## 📂 Data Sources

### 🔹 National Vulnerability Database (NVD)
- Official CVE JSON feeds  
- Real-time vulnerability disclosures  

### 🔹 Extracted & Processed Features

| Feature | Description |
|------|------------|
| CVE ID | Unique vulnerability identifier |
| Description | Natural language vulnerability details |
| Impact Score | CVSS base score |
| Attack Vector | Network / Local / Physical |
| Attack Complexity | Low / High |
| Privileges Required | None / Low / High |

---

## 🛠️ Technology Stack

### 🔸 Backend & Machine Learning
- **Python 3.10+**
- **Scikit-learn (Random Forest Classifier)**
- **TF-IDF Vectorization**
- Pandas, NumPy
- Joblib (Model persistence)

### 🔸 GenAI (Explainability Layer)
- **Open-Source LLM (Mistral / LLaMA)**
- **Ollama (Local LLM Runtime)**
- ✅ No paid APIs  
- ✅ Offline & privacy-friendly  

### 🔸 Visualization & UI
- **Streamlit**
- **Plotly**
- Interactive filters, KPIs & analytics

---

## 🧠 System Architecture

NVD CVE Feeds
      ↓
Data Preprocessing & Feature Engineering
      ↓
ML Prediction Engine (Random Forest)
      ↓
Severity Classification & Probability Scoring
      ↓
GenAI Explainability (Open-Source LLM)
      ↓
Interactive Streamlit Dashboard


---

## 📈 Machine Learning Workflow

### 🔹 Data Preprocessing
- Text normalization & cleaning  
- Missing value handling  
- Encoding categorical CVSS features  
- Binary classification:
  - **1 → HIGH / CRITICAL**
  - **0 → LOW / MEDIUM**

### 🔹 Feature Engineering
- TF-IDF vectors from vulnerability descriptions  
- Structured CVSS feature encoding  
- Feature alignment for stable inference  

### 🔹 Model Training
- Algorithm: **Random Forest Classifier**
- Baseline Accuracy: **~90.42%**
- Probability-based severity prediction  

### 🔹 Model Artifacts

| File | Purpose |
|---|---|
| `rf_model.pkl` | Trained ML model |
| `tfidf_vectorizer.pkl` | Text feature extractor |
| `cat_columns.pkl` | Categorical feature alignment |

---

## 📊 Key Features

- 📡 **Real-Time CVE Severity Prediction**
- 📊 **Interactive Dashboards & KPIs**
- 🔍 **Advanced Filtering & Keyword Search**
- 🧠 **AI-Generated Vulnerability Explanations**
- 📈 **Attack Vector & Trend Analysis**
- 💾 **Exportable Reports (CSV)**
- 🔐 **Fully Open-Source & Offline-Capable**

---

## 🚀 **How to Run Locally**

🔧 **1️⃣ Install Dependencies**

pip install -r requirements.txt

**2️⃣ Run the Dashboard**

streamlit run app.py

**3️⃣ (Optional) Enable Local LLM**

ollama pull mistral

**📊 Sample Output**
| CVE ID        | Attack Vector | Probability | Predicted Severity |
| ------------- | ------------- | ----------- | ------------------ |
| CVE-2024-XXXX | NETWORK       | 0.92        | 🔴 HIGH / CRITICAL |
| CVE-2024-YYYY | LOCAL         | 0.18        | 🟢 LOW / MEDIUM    |


**🔮 Future Enhancements**

Integration of deep learning models (BERT, SecurityBERT, LSTM)

Automated retraining pipelines

Threat intelligence correlation (Exploits, Malware, MITRE ATT&CK)

SIEM / SOC tool integration

Geographical threat visualization

Collaborative analyst validation portal

Cloud-native scalable deployment


**🌐 Deployment Options**

🌍 Streamlit Community Cloud (Free)

🤗 Hugging Face Spaces

🖥️ Local LAN Deployment

🐳 Docker-based Containers


**👨‍💻 Author**

JAYAPRAKASH P
Cybersecurity Researcher | Ethical Hacking Enthusiast | AI & GenAI Practitioner

**📜 License**

This project is intended for academic and research purposes only.

