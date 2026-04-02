import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import pickle
import os

# ──────────────────────────────────────────
# STEP 1 — Load Data
# ──────────────────────────────────────────
print("[*] Loading packet data...")
df = pd.read_csv("packet_log.csv")
print(f"[+] Loaded {len(df)} packets\n")
print(df.head())

# ──────────────────────────────────────────
# STEP 2 — Label attacks vs normal
# We label packets as 'attack' based on
# known attack patterns in our data
# ──────────────────────────────────────────
print("\n[*] Labeling attack traffic...")

def label_packet(row):
    # Port scan — small packets to many ports
    if row['protocol'] == 'TCP' and row['dst_port'] < 1024 and row['size'] < 60:
        return 'attack'
    # SYN flood — many TCP packets to port 80
    if row['protocol'] == 'TCP' and row['dst_port'] == 80 and row['size'] < 60:
        return 'attack'
    # ICMP flood
    if row['protocol'] == 'ICMP' and row['size'] < 100:
        return 'attack'
    # SSH brute force
    if row['protocol'] == 'TCP' and row['dst_port'] == 22:
        return 'attack'
    # HTTP brute force
    if row['protocol'] == 'TCP' and row['dst_port'] in [80, 8080] and row['size'] < 60:
        return 'attack'
    # DNS tunneling — large UDP packets to port 53
    if row['protocol'] == 'UDP' and row['dst_port'] == 53 and row['size'] > 100:
        return 'attack'
    return 'normal'

df['label'] = df.apply(label_packet, axis=1)

# Show label distribution
print(f"\n[+] Label distribution:")
print(df['label'].value_counts())

# ──────────────────────────────────────────
# STEP 3 — Feature Engineering
# Convert raw data into numbers ML can use
# ──────────────────────────────────────────
print("\n[*] Preparing features...")

# Encode protocol as number (TCP=0, UDP=1, ICMP=2, OTHER=3)
le = LabelEncoder()
df['protocol_enc'] = le.fit_transform(df['protocol'])

# Handle '-' in port columns
df['src_port'] = pd.to_numeric(df['src_port'], errors='coerce').fillna(0)
df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(0)

# Features we'll train on
features = ['protocol_enc', 'src_port', 'dst_port', 'size']
X = df[features]
y = df['label']

print(f"[+] Features: {features}")
print(f"[+] Total samples: {len(X)}")

# ──────────────────────────────────────────
# STEP 4 — Split into Train/Test sets
# 80% for training, 20% for testing
# ──────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
print(f"\n[+] Training samples: {len(X_train)}")
print(f"[+] Testing samples:  {len(X_test)}")

# ──────────────────────────────────────────
# STEP 5 — Train Random Forest Model
# ──────────────────────────────────────────
print("\n[*] Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,   # 100 decision trees
    random_state=42,
    max_depth=10
)
model.fit(X_train, y_train)
print("[+] Model trained!")

# ──────────────────────────────────────────
# STEP 6 — Evaluate the Model
# ──────────────────────────────────────────
print("\n[*] Evaluating model...")
y_pred = model.predict(X_test)

print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

accuracy = (y_pred == y_test).mean() * 100
print(f"✅ Model Accuracy: {accuracy:.2f}%")

# ──────────────────────────────────────────
# STEP 7 — Feature Importance Chart
# Shows which features matter most
# ──────────────────────────────────────────
print("\n[*] Generating feature importance chart...")
importances = model.feature_importances_
plt.figure(figsize=(8, 4))
plt.bar(features, importances, color=['#e74c3c','#3498db','#2ecc71','#f39c12'])
plt.title("Feature Importance — What the ML Model Looks At")
plt.xlabel("Feature")
plt.ylabel("Importance Score")
plt.tight_layout()
plt.savefig("feature_importance.png")
print("[+] Chart saved as feature_importance.png")

# ──────────────────────────────────────────
# STEP 8 — Save the trained model
# We'll load this in our live IDS later
# ──────────────────────────────────────────
with open("ids_model.pkl", "wb") as f:
    pickle.dump((model, le), f)
print("[+] Model saved as ids_model.pkl")

print("\n🎉 Training complete! Ready for live detection.")
