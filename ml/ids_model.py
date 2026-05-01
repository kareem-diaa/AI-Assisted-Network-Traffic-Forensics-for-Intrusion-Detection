import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time
import glob

print("Loading CSVs...")
dfs = []
for f in glob.glob("*.csv"):
    try:
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
        print(f"  Loaded {f}: {df.shape}")
    except Exception as e:
        print(f"  Skipped {f}: {e}")

df = pd.concat(dfs, ignore_index=True)
print(f"Combined: {df.shape}")

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

df['label'] = df['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)
print(f"Class distribution:\n{df['label'].value_counts()}")

drop_cols = ['Label','Flow ID','Source IP','Destination IP','Source Port','Destination Port','Timestamp']
df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True)

X = df.drop('label', axis=1)
y = df['label']

# Top 20 features by correlation
corr = df.corr()['label'].abs().sort_values(ascending=False)
top_features = corr[1:21].index.tolist()
X = X[top_features]
print(f"Top 5 features: {top_features[:5]}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42, class_weight='balanced'),
    'Decision Tree': DecisionTreeClassifier(max_depth=10, random_state=42),
    'Logistic Regression': LogisticRegression(max_iter=500, random_state=42)
}

results = {}
best_model, best_auc, best_name = None, 0, ""

for name, model in models.items():
    print(f"\nTraining {name}...")
    t0 = time.time()
    model.fit(X_train_s, y_train)
    elapsed = time.time() - t0
    y_pred = model.predict(X_test_s)
    y_proba = model.predict_proba(X_test_s)[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    acc = accuracy_score(y_test, y_pred)
    results[name] = {'Accuracy': round(acc,4), 'ROC-AUC': round(auc,4), 'Train Time (s)': round(elapsed,2)}
    print(classification_report(y_test, y_pred, target_names=['Benign','Attack']))
    if auc > best_auc:
        best_auc, best_model, best_name = auc, model, name

comp = pd.DataFrame(results).T
print("\n--- Model Comparison ---")
print(comp)
comp.to_csv('model_comparison.csv')

# Confusion matrix
cm = confusion_matrix(y_test, best_model.predict(X_test_s))
plt.figure(figsize=(7,5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Benign','Attack'], yticklabels=['Benign','Attack'])
plt.title(f'Confusion Matrix — {best_name}')
plt.tight_layout()
plt.savefig('confusion_matrix.png', dpi=150)
print("Saved confusion_matrix.png")

# Feature importance
rf = models['Random Forest']
pd.Series(rf.feature_importances_, index=top_features).nlargest(15).plot(
    kind='barh', figsize=(9,6), color='steelblue')
plt.title('Top 15 Features — Random Forest')
plt.tight_layout()
plt.savefig('feature_importance.png', dpi=150)
print("Saved feature_importance.png")

# Class distribution
pd.Series({'Benign': int((y==0).sum()), 'Attack': int((y==1).sum())}).plot(
    kind='bar', color=['green','red'], figsize=(6,4))
plt.title('Traffic Label Distribution')
plt.xticks(rotation=0)
plt.tight_layout()
plt.savefig('class_distribution.png', dpi=150)

joblib.dump(best_model, 'ids_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
print(f"\nDone. Best: {best_name} (AUC={best_auc:.4f})")
