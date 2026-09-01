# Phishing URL Detection System

## PROBLEM STATEMENT
Phishing attacks remain one of the most prevalent cybersecurity threats, tricking users into revealing sensitive credentials or downloading malware through deceptively crafted URLs. Traditional blacklist-based detection systems often fail to identify zero-day phishing domains because they rely on exact domain matching.

## OBJECTIVE
To build a lightweight, fast, and secure Machine Learning system capable of detecting zero-day phishing URLs using purely static lexical analysis, without requiring network requests or visits to the potentially malicious sites.

## FEATURES
- **Zero-Touch Analysis:** Analyzes the URL purely as a string, ensuring the application never visits or executes potentially malicious code.
- **Machine Learning Engine:** Utilizes a Random Forest classifier trained on a balanced dataset of legitimate and phishing URLs.
- **Real-Time Risk Scoring:** Provides a 0-100 risk score and a clear security verdict.
- **Diagnostic Insights:** Extracts and displays human-readable security indicators (e.g., presence of IPs, suspicious keywords, missing HTTPS).
- **Premium UI:** Features a sleek, responsive, cyberpunk-inspired monochrome interface with butter-smooth animations.

## TECHNOLOGY STACK
- **Backend:** Python 3, Flask
- **Machine Learning:** Scikit-learn, Pandas, Numpy, Joblib
- **Frontend:** HTML5, CSS3, Vanilla JavaScript (No React/Node.js overhead)

## SYSTEM ARCHITECTURE
The request and processing flow operates completely locally:
User ↓
URL Input ↓
Feature Extraction ↓
Random Forest ↓
Phishing Probability ↓
Risk Score ↓
Security Verdict

## FEATURE EXTRACTION
The system statically extracts the following numerical features from any given URL:
1. **URL Length:** Phishing URLs are often unusually long to obscure the true domain.
2. **Dot Count:** Excessive subdomains (dots) are used to mimic legitimate paths.
3. **Hyphen Count:** Used commonly in deceptive domains (e.g., `secure-login-verify`).
4. **Special Characters:** Counts symbols like `@`, `?`, `=`, `%`, which often indicate complex tracking or obfuscated credentials.
5. **@ Symbol Presence:** Used to ignore everything preceding the `@` symbol in basic auth URLs.
6. **IP Address Presence:** Direct IPs are rarely used for legitimate consumer endpoints.
7. **HTTPS Presence:** Indicates whether the connection is encrypted (though not a guarantee of safety).
8. **Subdomain Count:** Deeply nested subdomains attempt to fool users.
9. **Suspicious Keywords:** Counts occurrences of words like `login`, `verify`, `account`, `banking`, `secure`.
10. **Shortening Services:** Detects usage of `bit.ly`, `tinyurl.com`, etc., commonly used to mask destinations.

## MACHINE LEARNING
- **Dataset:** Contains 1,000 synthetically generated, diverse URLs (500 legitimate, 500 phishing) to teach generalized patterns rather than memorizing a small list.
- **Train/Test Split:** Standard 80/20 split used during the training phase.
- **Random Forest:** An ensemble decision-tree classifier chosen for its resistance to overfitting and high accuracy on categorical/lexical features.
- **Prediction Probability:** The model outputs a continuous probability (0.0 to 1.0) rather than a binary class, which is translated directly into the Risk Score.
- **Evaluation Metrics:** On the test set, the model achieves near-perfect separation (100% Accuracy, Precision, Recall, and F1-score) based on the clear lexical boundaries of the synthetic dataset.

## INSTALLATION

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the environment:
**macOS/Linux:**
```bash
source venv/bin/activate
```
**Windows:**
```bash
venv\Scripts\activate
```

3. Install requirements:
```bash
pip install -r requirements.txt
```

4. Train the ML model:
```bash
python src/train_model.py
```

5. Run the server:
```bash
python app.py
```

The application will be running locally at: **http://127.0.0.1:5001**

## TESTING
You can safely use the following fictional demo URLs to test the application's response logic:
- **SAFE:** `https://www.example.com`
- **SUSPICIOUS:** `http://secure-login-verify-example.com/account/login`
- **IP-BASED:** `http://192.0.2.10/login`

## SECURITY
**CRITICAL:** This application performs strictly **static URL analysis**. It parses the URL string and extracts lexical features locally. It **does not** open, visit, crawl, ping, or execute the submitted URLs in any way. No API keys are required and user input is treated as plain text.

## LIMITATIONS
URL-based static analysis is incredibly fast and safe, but it cannot detect every phishing attack. It will not catch phishing campaigns hosted on compromised legitimate domains (e.g., a hacked WordPress site) if the URL path itself does not exhibit classic phishing lexical structures.

## FUTURE IMPROVEMENTS
- Larger datasets for better real-world generalization
- Threat intelligence API integration
- Domain age and reputation analysis
- DNS resolution analysis
- Real-time security feeds
- More advanced ML models (e.g., deep learning on character sequences)

---

## CV PROJECT DESCRIPTION
- Engineered a zero-touch Phishing URL Detection System using a Random Forest classifier to perform static lexical analysis, achieving robust local predictions without risking network interaction with malicious endpoints.
- Developed a lightweight, full-stack application integrating a Python/Flask ML backend with a custom, high-performance vanilla JavaScript and CSS frontend, eliminating heavy framework overhead.
- **Technologies:** Python, Flask, Scikit-learn, Pandas, Numpy, HTML5, CSS3, Vanilla JS.
