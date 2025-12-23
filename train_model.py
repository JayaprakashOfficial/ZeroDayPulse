import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.utils import resample, class_weight
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

print("🚀 Training AI model for ZeroDayPulse...")

# -----------------------------
# 1. Load dataset
# -----------------------------
df = pd.read_csv(
    "nvd_recent.csv",
    engine="python",
    quotechar='"',
    on_bad_lines="skip"
)
print(f"✅ Loaded dataset with {len(df)} records.")

# -----------------------------
# 2. Handle missing values
# -----------------------------
df.fillna({
    "Description": "",
    "Impact_Score": 0,
    "Attack_Vector": "N/A",
    "Attack_Complexity": "N/A",
    "Privileges_Required": "N/A",
    "Severity": "LOW"
}, inplace=True)

# -----------------------------
# 3. Binary label encoding
# -----------------------------
df["Label"] = df["Severity"].apply(lambda x: 1 if str(x).upper() in ["HIGH", "CRITICAL"] else 0)

# -----------------------------
# 4. Balance dataset (upsample minority)
# -----------------------------
df_majority = df[df.Label == 0]
df_minority = df[df.Label == 1]

df_minority_upsampled = resample(
    df_minority,
    replace=True,
    n_samples=len(df_majority),
    random_state=42
)

df_balanced = pd.concat([df_majority, df_minority_upsampled])
df_balanced = df_balanced.sample(frac=1, random_state=42).reset_index(drop=True)
print(f"⚖️ Balanced dataset: {len(df_balanced)} records")

# -----------------------------
# 5. TF-IDF for description text
# -----------------------------
tfidf = TfidfVectorizer(
    max_features=8000,
    ngram_range=(1, 2),
    stop_words="english"
)
X_text = tfidf.fit_transform(df_balanced["Description"])

# -----------------------------
# 6. Encode categorical features
# -----------------------------
categorical_cols = ["Attack_Vector", "Attack_Complexity", "Privileges_Required"]
X_cat = pd.get_dummies(df_balanced[categorical_cols])

# -----------------------------
# 7. Combine features
# -----------------------------
X = np.hstack((X_text.toarray(), X_cat.values))
y = df_balanced["Label"]

# Optional scaling for numeric stability
scaler = StandardScaler(with_mean=False)
X = scaler.fit_transform(X)

# -----------------------------
# 8. Compute class weights dynamically
# -----------------------------
classes = np.unique(y)
weights = class_weight.compute_class_weight(class_weight='balanced', classes=classes, y=y)
class_weights = {cls: w for cls, w in zip(classes, weights)}

# -----------------------------
# 9. Train/Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"🧩 Training on {len(X_train)} samples, testing on {len(X_test)} samples")

# -----------------------------
# 10. Hyperparameter Tuning (Random Forest)
# -----------------------------
param_grid = {
    'n_estimators': [200, 300],
    'max_depth': [10, 20, None],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2]
}

rf = RandomForestClassifier(random_state=42, class_weight=class_weights)
grid = GridSearchCV(rf, param_grid, cv=3, scoring="f1", n_jobs=-1, verbose=1)
grid.fit(X_train, y_train)

model = grid.best_estimator_
print(f"🏆 Best parameters: {grid.best_params_}")

# -----------------------------
# 11. Evaluation
# -----------------------------
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model trained! Accuracy: {accuracy*100:.2f}%")

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

print("🧠 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# -----------------------------
# 12. Save trained artifacts
# -----------------------------
joblib.dump(model, "rf_model.pkl")
joblib.dump(tfidf, "tfidf_vectorizer.pkl")
joblib.dump(list(X_cat.columns), "cat_columns.pkl")

print("\n💾 Saved rf_model.pkl, tfidf_vectorizer.pkl, and cat_columns.pkl")
print("\n✅ Training complete — model optimized for **real-time prediction** with class balancing and TF-IDF enhancement.")
