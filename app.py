from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse
import math
import re

app = Flask(__name__)
CORS(app)  # allow frontend connection

# -------------------------------
# Load trained model
# -------------------------------
model = joblib.load("phishing_detector.pkl")

# Load feature columns from dataset
data = pd.read_csv("dataset.csv")
FEATURE_COLUMNS = data.drop(columns=["Type"]).columns.tolist()

# -------------------------------
# Entropy function
# -------------------------------
def entropy(string):
    if not string:
        return 0
    prob = [string.count(c) / len(string) for c in dict.fromkeys(list(string))]
    return -sum(p * math.log2(p) for p in prob if p > 0)

# -------------------------------
# Feature extraction (41 features)
# -------------------------------
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    f = {}

    f['url_length'] = len(url)
    f['number_of_dots_in_url'] = url.count('.')
    f['having_repeated_digits_in_url'] = int(bool(re.search(r'(\d)\1+', url)))
    f['number_of_digits_in_url'] = sum(c.isdigit() for c in url)
    f['number_of_special_char_in_url'] = sum(not c.isalnum() for c in url)
    f['number_of_hyphens_in_url'] = url.count('-')
    f['number_of_underline_in_url'] = url.count('_')
    f['number_of_slash_in_url'] = url.count('/')
    f['number_of_questionmark_in_url'] = url.count('?')
    f['number_of_equal_in_url'] = url.count('=')
    f['number_of_at_in_url'] = url.count('@')
    f['number_of_dollar_in_url'] = url.count('$')
    f['number_of_exclamation_in_url'] = url.count('!')
    f['number_of_hashtag_in_url'] = url.count('#')
    f['number_of_percent_in_url'] = url.count('%')

    f['domain_length'] = len(domain)
    f['number_of_dots_in_domain'] = domain.count('.')
    f['number_of_hyphens_in_domain'] = domain.count('-')
    f['having_special_characters_in_domain'] = int(any(not c.isalnum() for c in domain))
    f['number_of_special_characters_in_domain'] = sum(not c.isalnum() for c in domain)
    f['having_digits_in_domain'] = int(any(c.isdigit() for c in domain))
    f['number_of_digits_in_domain'] = sum(c.isdigit() for c in domain)
    f['having_repeated_digits_in_domain'] = int(bool(re.search(r'(\d)\1+', domain)))

    subdomains = domain.split('.')[:-2]
    f['number_of_subdomains'] = len(subdomains)
    f['having_dot_in_subdomain'] = int(any('.' in s for s in subdomains))
    f['having_hyphen_in_subdomain'] = int(any('-' in s for s in subdomains))
    f['average_subdomain_length'] = np.mean([len(s) for s in subdomains]) if subdomains else 0
    f['average_number_of_dots_in_subdomain'] = np.mean([s.count('.') for s in subdomains]) if subdomains else 0
    f['average_number_of_hyphens_in_subdomain'] = np.mean([s.count('-') for s in subdomains]) if subdomains else 0
    f['having_special_characters_in_subdomain'] = int(any(not c.isalnum() for s in subdomains for c in s))
    f['number_of_special_characters_in_subdomain'] = sum(not c.isalnum() for s in subdomains for c in s)
    f['having_digits_in_subdomain'] = int(any(c.isdigit() for s in subdomains for c in s))
    f['number_of_digits_in_subdomain'] = sum(c.isdigit() for s in subdomains for c in s)
    f['having_repeated_digits_in_subdomain'] = int(bool(re.search(r'(\d)\1+', ''.join(subdomains))))

    f['having_path'] = int(bool(path))
    f['path_length'] = len(path)
    f['having_query'] = int(bool(query))
    f['having_fragment'] = int(bool(fragment))
    f['having_anchor'] = int('#' in url)

    f['entropy_of_url'] = entropy(url)
    f['entropy_of_domain'] = entropy(domain)

    return f

# -------------------------------
# API Endpoint
# -------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"prediction": "Invalid URL"})

    features = extract_features(url)
    df = pd.DataFrame([features])
    df = df[FEATURE_COLUMNS]  # exact order

    prediction = model.predict(df)[0]

    result = "⚠️ Phishing Website" if prediction == 1 else "✅ Legitimate Website"
    return jsonify({"prediction": result})

# -------------------------------
# Run server
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)
