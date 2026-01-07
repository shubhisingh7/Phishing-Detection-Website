# Phishing-Detection-Website
Phishing Website Detection System (Machine Learning + Cyber Security)
📌 Project Overview
This project implements an intelligent phishing website detection system using Machine Learning and Cyber Security techniques. The system analyzes the lexical, structural, and statistical characteristics of URLs to classify them as legitimate or phishing in real time. It helps users identify malicious websites before they become victims of online fraud.

🚀 Key Features
🔍 Real-time URL analysis using a trained ML model
🤖 Random Forest classifier trained on ~247,000 URLs
🧠 41+ engineered features (URL, domain, subdomain, entropy-based)
🌐 Interactive web interface for user-friendly detection
🔌 Flask REST API backend for model serving
⚡ Handles false positives using explainable feature-based logic
🧠 Machine Learning Approach

Dataset: Phishing Detection Dataset (247,950 URLs)

Target Labels:
0 → Legitimate Website
1 → Phishing Website

Model Used: Random Forest Classifier
Evaluation Metrics: Accuracy, Precision, Recall, F1-score
Achieved Accuracy: ~91–92%

🧩 Feature Engineering
The system extracts 41 different features from each URL, including:
URL length, number of dots, digits, and special characters
Domain and subdomain structure analysis
Path, query, fragment presence
Entropy of URL and domain (randomness detection)
Detection of repeated digits and suspicious patterns

🌐 System Architecture
User (Browser)
     ↓
Frontend (HTML + CSS + JavaScript)
     ↓
Flask REST API
     ↓
Feature Extraction Engine
     ↓
Random Forest ML Model
     ↓
Prediction Result

🛠️ Tech Stack
Programming Language: Python
Machine Learning: Scikit-learn
Backend: Flask, Flask-CORS
Frontend: HTML, CSS, JavaScript
Data Processing: Pandas, NumPy
Model Persistence: Joblib

📂 Project Structure
phishing-website-detection/
│
├── app.py                     # Flask backend API
├── phishing_detection.py      # Model training & testing
├── phishing_detector.pkl      # Trained ML model
├── dataset.csv                # Phishing detection dataset
├── index.html                 # Frontend UI
└── README.md                  # Project documentation

▶️ How to Run the Project
Clone the repository
Install required dependencies
pip install -r requirements.txt
Train the model (optional if model already exists)
python phishing_detection.py
Start the Flask backend
python app.py
Open index.html in a browser and test URLs

⚠️ Limitations
The model relies on lexical and statistical URL features only
Domain reputation, WHOIS data, and blacklist APIs are not included
May produce false positives for newly registered or short domains

🔮 Future Enhancements
Integration with Google Safe Browsing / VirusTotal APIs
Adding domain age and SSL certificate validation
Deploying as a cloud-based web application
Using advanced models like XGBoost or Deep Learning

🎓 Academic Relevance
This project demonstrates:
Practical application of Machine Learning in Cyber Security
Strong understanding of feature engineering
End-to-end full-stack ML deployment
Real-world handling of false positives and model bias
