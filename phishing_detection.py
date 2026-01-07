import pandas as pd
import numpy as np
import math
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import re

# -------------------------------
# 1️⃣ Entropy Function
# -------------------------------
def entropy(string):
    prob = [string.count(c) / len(string) for c in dict.fromkeys(list(string))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

# -------------------------------
# 2️⃣ Feature Extraction (41 FEATURES)
# -------------------------------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    features = {}

    # URL-based features
    features['url_length'] = len(url)
    features['number_of_dots_in_url'] = url.count('.')
    features['having_repeated_digits_in_url'] = int(bool(re.search(r'(\d)\1+', url)))
    features['number_of_digits_in_url'] = sum(c.isdigit() for c in url)
    features['number_of_special_char_in_url'] = sum(not c.isalnum() for c in url)
    features['number_of_hyphens_in_url'] = url.count('-')
    features['number_of_underline_in_url'] = url.count('_')
    features['number_of_slash_in_url'] = url.count('/')
    features['number_of_questionmark_in_url'] = url.count('?')
    features['number_of_equal_in_url'] = url.count('=')
    features['number_of_at_in_url'] = url.count('@')
    features['number_of_dollar_in_url'] = url.count('$')
    features['number_of_exclamation_in_url'] = url.count('!')
    features['number_of_hashtag_in_url'] = url.count('#')
    features['number_of_percent_in_url'] = url.count('%')

    # Domain features
    features['domain_length'] = len(domain)
    features['number_of_dots_in_domain'] = domain.count('.')
    features['number_of_hyphens_in_domain'] = domain.count('-')
    features['having_special_characters_in_domain'] = int(any(not c.isalnum() for c in domain))
    features['number_of_special_characters_in_domain'] = sum(not c.isalnum() for c in domain)
    features['having_digits_in_domain'] = int(any(c.isdigit() for c in domain))
    features['number_of_digits_in_domain'] = sum(c.isdigit() for c in domain)
    features['having_repeated_digits_in_domain'] = int(bool(re.search(r'(\d)\1+', domain)))

    # Subdomain features
    subdomains = domain.split('.')[:-2]
    features['number_of_subdomains'] = len(subdomains)
    features['having_dot_in_subdomain'] = int(any('.' in s for s in subdomains))
    features['having_hyphen_in_subdomain'] = int(any('-' in s for s in subdomains))
    features['average_subdomain_length'] = np.mean([len(s) for s in subdomains]) if subdomains else 0
    features['average_number_of_dots_in_subdomain'] = np.mean([s.count('.') for s in subdomains]) if subdomains else 0
    features['average_number_of_hyphens_in_subdomain'] = np.mean([s.count('-') for s in subdomains]) if subdomains else 0
    features['having_special_characters_in_subdomain'] = int(any(not c.isalnum() for s in subdomains for c in s))
    features['number_of_special_characters_in_subdomain'] = sum(not c.isalnum() for s in subdomains for c in s)
    features['having_digits_in_subdomain'] = int(any(c.isdigit() for s in subdomains for c in s))
    features['number_of_digits_in_subdomain'] = sum(c.isdigit() for s in subdomains for c in s)
    features['having_repeated_digits_in_subdomain'] = int(bool(re.search(r'(\d)\1+', ''.join(subdomains))))

    # Path & query
    features['having_path'] = int(bool(path))
    features['path_length'] = len(path)
    features['having_query'] = int(bool(query))
    features['having_fragment'] = int(bool(fragment))
    features['having_anchor'] = int('#' in url)

    # Entropy
    features['entropy_of_url'] = entropy(url)
    features['entropy_of_domain'] = entropy(domain)

    return features

# -------------------------------
# 3️⃣ Load Dataset
# -------------------------------
data = pd.read_csv("dataset.csv")
X = data.drop(columns=['Type'])
y = data['Type']

# -------------------------------
# 4️⃣ Train Model
# -------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train, y_train)

# -------------------------------
# 5️⃣ Evaluation
# -------------------------------
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

joblib.dump(model, "phishing_detector.pkl")
print("\nModel saved as phishing_detector.pkl")

# -------------------------------
# 6️⃣ Predict New URL
# -------------------------------
def predict_url(url):
    features = extract_features(url)
    df = pd.DataFrame([features])
    df = df[X.columns]  # exact column order
    result = model.predict(df)[0]
    return "⚠️ Phishing Website" if result == 1 else "✅ Legitimate Website"

# -------------------------------
# 7️⃣ Interactive Mode
# -------------------------------
print("\n=== Phishing Website Detection System ===")
while True:
    url = input("\nEnter URL (or type 'exit' to quit): ")
    if url.lower() == 'exit':
        break
    print("Prediction:", predict_url(url))
