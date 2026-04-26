import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib, json, os

print("=== PFE SOC - Entraînement ML sur CIC-IDS2017 ===\n")

# Charge uniquement Tuesday (Brute Force SSH/FTP) + Friday Morning
files = {
    "tuesday.csv": "Tuesday-WorkingHours.pcap_ISCX.csv",
    "friday_morning": "Friday-WorkingHours-Morning.pcap_ISCX.csv"
}

dataset_dir = os.path.expanduser("~/pfe_soc/dataset/")
dfs = []
for fname in ["Tuesday-WorkingHours.pcap_ISCX.csv",
              "Friday-WorkingHours-Morning.pcap_ISCX.csv"]:
    path = os.path.join(dataset_dir, fname)
    if os.path.exists(path):
        print(f"Chargement : {fname}")
        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)

df = pd.concat(dfs, ignore_index=True)
print(f"Shape total : {df.shape}")
print(f"\nDistribution des classes :")
print(df['Label'].value_counts())

# Nettoyage
df = df.replace([np.inf, -np.inf], np.nan).dropna()
print(f"Shape après nettoyage : {df.shape}")

# Features
FEATURES = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'Fwd Packet Length Mean',
    'Bwd Packet Length Mean', 'SYN Flag Count', 'ACK Flag Count',
    'PSH Flag Count', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length',
    'Max Packet Length', 'Packet Length Mean', 'Packet Length Std'
]
available = [f for f in FEATURES if f in df.columns]
print(f"\nFeatures ({len(available)}) : OK")

X = df[available]
y = (df['Label'] != 'BENIGN').astype(int)
print(f"Classes : {dict(y.value_counts())} (0=Normal, 1=Attaque)")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y)

print("\nEntraînement Random Forest (100 arbres)...")
model = RandomForestClassifier(
    n_estimators=100, max_depth=15,
    random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

print("\n=== RÉSULTATS ===")
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred,
      target_names=['Normal', 'Attaque']))

cm = confusion_matrix(y_test, y_pred)
print(f"Matrice de confusion :")
print(f"  TN={cm[0][0]:>6}  FP={cm[0][1]:>6}")
print(f"  FN={cm[1][0]:>6}  TP={cm[1][1]:>6}")
print(f"Taux faux positifs : {cm[0][1]/(cm[0][0]+cm[0][1])*100:.4f}%")

fi = pd.Series(model.feature_importances_, index=available)
print(f"\nTop 5 features importantes :")
print(fi.nlargest(5).to_string())

os.makedirs(os.path.expanduser("~/pfe_soc/models"), exist_ok=True)
joblib.dump(model, os.path.expanduser("~/pfe_soc/models/model_rf.pkl"))
json.dump(available, open(
    os.path.expanduser("~/pfe_soc/models/features.json"), 'w'))
print("\nModele sauvegarde : ~/pfe_soc/models/model_rf.pkl")
