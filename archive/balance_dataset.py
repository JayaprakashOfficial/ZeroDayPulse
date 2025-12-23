import pandas as pd
from sklearn.utils import resample

df = pd.read_csv("cve_labeled.csv")

# Separate majority and minority classes
majority = df[df.Label == 0]
minority = df[df.Label == 1]

# Upsample the minority class
minority_upsampled = resample(minority, 
                              replace=True,     # sample with replacement
                              n_samples=len(majority), # match majority
                              random_state=42)

# Combine back together
df_balanced = pd.concat([majority, minority_upsampled])

df_balanced.to_csv("cve_balanced.csv", index=False)

print("✅ Dataset balanced successfully.")
print(df_balanced['Label'].value_counts())
