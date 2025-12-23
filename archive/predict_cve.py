import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler

# Load trained model + vectorizer + categorical schema
model = joblib.load("rf_model.pkl")
tfidf = joblib.load("tfidf_vectorizer.pkl")
cat_columns = joblib.load("cat_columns.pkl")

def predict_cve(df):
    """Run real-time AI predictions identical to training pipeline"""

    if df.empty:
        return pd.DataFrame()

    # Handle missing values
    df.fillna({
        "Description": "",
        "Impact_Score": 0,
        "Attack_Vector": "N/A",
        "Attack_Complexity": "N/A",
        "Privileges_Required": "N/A",
    }, inplace=True)

    # TF-IDF (same transformation as training)
    X_text = tfidf.transform(df["Description"])
    X_text_array = X_text.toarray()

    # One-hot encode categorical
    cat_input = pd.get_dummies(df[["Attack_Vector", "Attack_Complexity", "Privileges_Required"]])

    # Align columns
    for col in cat_columns:
        if col not in cat_input.columns:
            cat_input[col] = 0
    cat_input = cat_input[cat_columns]

    # Combine features
    X_input = np.hstack((X_text_array, cat_input.values))

    # Scale same as training
    scaler = StandardScaler(with_mean=False)
    X_input = scaler.fit_transform(X_input)

    # Predict
    probs = model.predict_proba(X_input)[:, 1]
    preds = model.predict(X_input)

    df["Predicted_Label"] = preds
    df["Probability_HighCritical"] = probs
    df["Predicted_Severity"] = df["Predicted_Label"].apply(lambda x: "HIGH/CRITICAL" if x == 1 else "LOW/MEDIUM")

    return df
