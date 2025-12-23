import pandas as pd

df = pd.read_csv("cve_training_data.csv")

# Label: 1 for High/Critical, 0 for Low/Medium
df["Label"] = df["Base_Score"].apply(lambda x: 1 if x >= 7.0 else 0)

df.to_csv("cve_labeled.csv", index=False)

print("✅ Data labeled successfully.")
print(df["Label"].value_counts())
