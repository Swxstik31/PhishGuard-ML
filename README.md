# PhishGuard-ML

## Overview
PhishGuard-ML is a machine-learning powered application that detects phishing and malicious URLs in real-time. It uses purely static lexical analysis to identify structural anomalies and security risks in URLs without ever visiting or resolving the target endpoints.

## Problem Statement
Traditional threat intelligence relies heavily on dynamic analysis (crawling URLs) or blocklists (DNS/WHOIS records), which are often slow, resource-intensive, or ineffective against newly generated zero-day phishing domains. 

## Solution
PhishGuard-ML solves this by utilizing machine learning to mathematically evaluate the string structure of a URL. By analyzing character frequencies, entropy, path lengths, and security-specific keywords, the application can instantly assess the probability of a URL being malicious before it is ever clicked or crawled.

## Key Features
- **Static URL Analysis:** Safely analyzes URLs strictly as strings.
- **Explainable AI (XAI):** Translates raw ML feature scores into human-readable risk factors.
- **Model Interpretability:** Exposes the internal logistic regression coefficients to show which global signals drive risk.
- **Privacy-First Architecture:** Keeps your analysis history strictly local via browser `localStorage`.
- **Security Dashboards:** Generates local analytics and visual threat distributions.
- **PDF Report Generation:** Compiles and exports structured cybersecurity teardowns natively on the client.
- **Adversarial Robustness Testing:** Includes a local testing suite to measure model stability against URL manipulation.

## Technology Stack
- **Backend:** Python, Flask, Gunicorn
- **Machine Learning:** Scikit-Learn, Pandas, Numpy, Joblib
- **Frontend:** Vanilla JavaScript, HTML5, CSS3
- **Local PDF Generation:** jsPDF, jsPDF-AutoTable

## System Architecture
The application runs as a decoupled API layer and a client-side frontend:
- The **Flask API** strictly ingests URLs and returns JSON predictions.
- The **Frontend JS** manages state, calculates local history, renders charts, and creates PDFs.

## ML Pipeline
```text
URL
↓
Input Validation
↓
27 Static URL Features
↓
Logistic Regression
↓
Phishing Probability
↓
Risk Score
↓
Explainable Risk Factors
```

## Dataset
The model was trained on a 10,000-sample real-world dataset combining:
- **Malicious URLs:** 5,000 active malware and phishing endpoints from **URLhaus**.
- **Legitimate URLs:** 5,000 top root domains from the **Tranco Top 1M** list.

*Dataset Limitations: The dataset inherently separates extremely clean root domains (Tranco) from deep, nested malware endpoints (URLhaus). This stark lexical boundary makes the model highly accurate against blatant malware but potentially overly sensitive to long, complex legitimate paths.*

## Machine Learning
During development, the following models were evaluated using a stratified 80/20 split:
- Logistic Regression
- Decision Tree
- Random Forest
- Support Vector Machine (SVM)
- Gradient Boosting

**Selected Production Model:** Logistic Regression. 
Because the stark dataset boundaries allowed all models to achieve near-perfect ROC-AUC metrics on the test split, Logistic Regression was selected as the production model due to its extreme inference speed, low memory footprint, and high interpretability. The model analyzes **27** distinct lexical features.

*IMPORTANT: High benchmark performance on this specific dataset does not guarantee real-world detection accuracy against advanced, targeted phishing campaigns.*

## Security Design
- **Static Analysis Only:** The application NEVER intentionally visits, crawls, resolves (DNS), or executes any submitted URL.
- **Input Validation:** Rejecting empty, non-string, or oversized (> 2048 char) inputs with clean HTTP 400 responses.
- **Security Headers:** Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a strict `Content-Security-Policy`.
- **Rate Limiting:** Implements lightweight in-memory request throttling to prevent API abuse.
- **Privacy-Safe Logging:** Logs only request metadata. Submitted URLs are never persistently logged.

## Explainable AI
The backend features a post-prediction layer that maps high-risk numerical thresholds (e.g., `entropy_hostname > 4.0`) to human-readable explanations, providing operators with actionable context.

## Feature Importance
Users can dynamically view the highest-weighted Logistic Regression coefficients in the UI to understand which structural features globally increase or decrease risk.

## Prediction History
A privacy-first logging system that tracks up to 50 recent analyses entirely inside the browser's `localStorage`.

## Security Dashboard
A real-time analytics layer that calculates total scans, threat distributions, and 7-day volume charts directly from the local browser cache without any external telemetry.

## Security Report
Users can instantly compile their analysis results into a clean, professional PDF document. PDF rendering is executed 100% locally via jsPDF to ensure no sensitive URL data is exfiltrated to external APIs.

## Adversarial Robustness Testing
An automated synthetic testing module (`src/adversarial_test.py`) that bombards the model with mutated URLs to evaluate how resilient the heuristic boundaries are against spoofing.

## API Documentation

### `GET /health`
Returns the status of the API and the loaded model.
```json
{
  "status": "ok",
  "model": "available"
}
```

### `POST /predict`
Analyzes a URL string and returns the risk evaluation.
**Request Body:**
```json
{
  "url": "https://www.example.com"
}
```

### `GET /feature-importance`
Returns the ranked list of Logistic Regression coefficients.

## Installation
Ensure you have Python 3.9+ installed.
```bash
git clone https://github.com/Swxstik31/PhishGuard-ML.git
cd PhishGuard-ML
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
pip install -r requirements.txt
```

## Running Locally
```bash
export FLASK_ENV=development
python app.py
```
The application will be available at `http://127.0.0.1:5001`.

## Production Deployment
PhishGuard-ML is designed to be deployed on any Python-capable hosting platform (such as Render, Heroku, AWS Elastic Beanstalk, or a VPS).

To run in production, use a WSGI server like Gunicorn:
```bash
export FLASK_ENV=production
gunicorn -b 0.0.0.0:5001 app:app
```

## Limitations
- **Lexical/Static Limitations:** The model only "sees" the text of the URL. It cannot detect if a completely benign-looking domain has been temporarily compromised to host malware.
- **Dataset Constraints:** Training primarily on root domains vs. deep paths limits the model's exposure to highly sophisticated spear-phishing structures.
- **Probabilistic Predictions:** ML outputs are mathematical probabilities, not guarantees. High benchmark performance does not replace professional dynamic security analysis.

## Future Improvements
- Integrate a secondary dynamic threat-intel API layer.
- Expand the dataset to include highly sophisticated, obfuscated spear-phishing URLs.
- Implement more advanced Natural Language Processing (NLP) tokenization for keyword detection.
