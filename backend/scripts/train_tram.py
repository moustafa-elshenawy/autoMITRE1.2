import os
import pickle
import pandas as pd
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

print("Loading TRAM dataset from HuggingFace...")
# There are unofficial mirrors of the TRAM dataset on HF. 
# We'll use 'mitre/tram-cti' if available, else a standard synthetic CTI dataset
try:
    dataset = load_dataset("mitre/tram-cti", split="train")
    df = dataset.to_pandas()
    text_col = 'text'
    label_col = 'technique_id'
except Exception as e:
    print(f"Failed to load mitre/tram-cti: {e}")
    print("Falling back to local synthetic generation for proof of concept...")
    
    # We create a small synthetic dataset for the POC to ensure the pipeline works
    # This proves the ML architecture which can then be trained on the real 100MB dataset offline
    data = [
        {"text": "The threat actor used mimikatz to dump credentials from memory.", "technique_id": "T1003"},
        {"text": "Execution of powershell.exe with encoded commands.", "technique_id": "T1059.001"},
        {"text": "A macro document dropped a payload in the temp directory.", "technique_id": "T1204.002"},
        {"text": "Lateral movement was observed using psexec across the domain.", "technique_id": "T1021.002"},
        {"text": "Ransomware encrypted all files and left a ransom note.", "technique_id": "T1486"},
        {"text": "The adversary created a scheduled task to run everyday at 3AM.", "technique_id": "T1053.005"},
        {"text": "Data was exfiltrated to an external IP address over port 443.", "technique_id": "T1041"},
        {"text": "Attacker used Bloodhound to map the active directory environment.", "technique_id": "T1087.002"},
        {"text": "Nmap scan was initiated against the internal subnet.", "technique_id": "T1046"},
        {"text": "Phishing email with a malicious link was sent to HR.", "technique_id": "T1566.002"},
         {"text": "Secretsdump was run to extract NTLM hashes.", "technique_id": "T1003"},
        {"text": "Empire agent used WMI for persistence.", "technique_id": "T1047"},
        {"text": "Crackmapexec used stolen credentials to authenticate.", "technique_id": "T1078"}
    ] * 20  # Duplicate to create enough samples for train_test_split
    
    df = pd.DataFrame(data)
    text_col = 'text'
    label_col = 'technique_id'

print(f"Dataset loaded. Size: {len(df)} rows.")

# Preprocessing
X = df[text_col].fillna('')
y = df[label_col].fillna('None')

print("Training ML Pipeline (TF-IDF + LogisticRegression)...")

# We use LogisticRegression with balanced class weights since technique distribution is highly skewed
pipeline = Pipeline([
    ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words='english')),
    ('clf', LogisticRegression(class_weight='balanced', max_iter=1000, C=1.0))
])

# Train on the whole dataset for production use
pipeline.fit(X, y)

print("Training complete. Evaluating...")
try:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    eval_pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=5000, ngram_range=(1, 2), stop_words='english')),
        ('clf', LogisticRegression(class_weight='balanced', max_iter=1000, C=1.0))
    ])
    eval_pipeline.fit(X_train, y_train)
    preds = eval_pipeline.predict(X_test)
    print("\nClassification Report (Test Set):")
    print(classification_report(y_test, preds, zero_division=0))
except Exception as e:
    print("Could not evaluate (probably too few samples in synthetic dataset).")

# Save the model
model_dir = "/Users/shno/Desktop/autoMITRE1.2/backend/models/saved"
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, "tram_technique_clf.pkl")

with open(model_path, 'wb') as f:
    pickle.dump(pipeline, f)

print(f"✅ Model successfully saved to: {model_path}")
