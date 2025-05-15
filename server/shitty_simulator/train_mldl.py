import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

df = pd.read_csv("logs/baseline_logs.csv")
df.columns = df.columns.str.strip()  # Strip whitespaces from column headers

df['timestamp'] = pd.to_datetime(df['timestamp'])
df['hour'] = df['timestamp'].dt.hour
df['minute'] = df['timestamp'].dt.minute
df['second'] = df['timestamp'].dt.second
df['dayofweek'] = df['timestamp'].dt.dayofweek

# Only include valid categorical columns
cat_cols = [col for col in ['ip', 'user', 'device', 'endpoint', 'status_tag', 'detection'] if col in df.columns and col.strip()]

# Encode categorical
le_dict = {col: LabelEncoder().fit(df[col]) for col in cat_cols}
for col, le in le_dict.items():
    df[col] = le.transform(df[col])

num_cols = ['hour', 'dayofweek', 'status_code']
X = df[cat_cols + num_cols]
y = df['label']

print("X shape:", X.shape)
print(X)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred))
