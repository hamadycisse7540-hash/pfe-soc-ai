import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib, json, os

print("=== Entraînement v2 - Features compatibles Wazuh ===\n")

dataset_dir = os.path.expanduser("~/pfe_soc/dataset/")
dfs = []
for fname in os.listdir(dataset_dir):
    if fname.endswith('.csv'):
        path = os.path.join(dataset_dir, fname)
        print(f"Chargement : {fname}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
df = df.replace([np.inf, -np.inf], np.nan).dropna()

print(f"\nDistribution :\n{df['Label'].value_counts()}\n")

# Features simples dérivables depuis Wazuh
FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'SYN Flag Count',
    'ACK Flag Count',
    'PSH Flag Count',
    'RST Flag Count',
    'Fwd Packets/s',
    'Bwd Packets/s',
]
available = [f for f in FEATURES if f in df.columns]
print(f"Features : {available}")

X = df[available]
y = (df['Label'] != 'BENIGN').astype(int)

# Crée des features de règles Wazuh pour l'inférence
RULE_FEATURES = {
    'level': 0,
    'is_brute_force': 0,
    'is_auth_failure': 0,
    'fail_count': 0,
    'src_ip_count': 0,
}

# Ajoute des features synthétiques basées sur le contexte
df['rule_level'] = np.where(df['Label'] != 'BENIGN', 
                             np.random.randint(8, 15, len(df)),
                             np.random.randint(3, 7, len(df)))
df['is_brute'] = (df['Label'].isin(
    ['FTP-Patator', 'SSH-Patator', 'Brute Force'])).astype(int)
df['fail_count'] = np.where(df['Label'] != 'BENIGN',
                             np.random.randint(5, 50, len(df)),
                             np.random.randint(0, 3, len(df)))

FINAL_FEATURES = available + ['rule_level', 'is_brute', 'fail_count']
X = df[FINAL_FEATURES]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print("\nEntraînement...")
model = RandomForestClassifier(n_estimators=100, max_depth=15,
                                random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n=== RÉSULTATS ===")
print(classification_report(y_test, y_pred,
      target_names=['Normal', 'Attaque']))

cm = confusion_matrix(y_test, y_pred)
print(f"TN={cm[0][0]}  FP={cm[0][1]}")
print(f"FN={cm[1][0]}  TP={cm[1][1]}")

os.makedirs(os.path.expanduser("~/pfe_soc/models"), exist_ok=True)
joblib.dump(model, os.path.expanduser("~/pfe_soc/models/model_v2.pkl"))
json.dump(FINAL_FEATURES, open(
    os.path.expanduser("~/pfe_soc/models/features_v2.json"), 'w'))
print("\nModele v2 sauvegarde !")
