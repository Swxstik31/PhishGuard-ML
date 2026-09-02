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
The system statically extracts the following **27 numerical features** from any given URL:

**Length & Ratios:**
1. URL Length, Domain Length, Path Length, Query Length
2. Ratio of Digits to total URL length

**Component Counts:**
3. Dots (`.`), Hyphens (`-`), Digits, Slashes (`/`), Underscores (`_`)
4. Special Characters (`@`, `?`, `=`, `&`, `%`, `_`, `/`), `@` characters, `=` characters, `&` characters, `%` characters
5. Subdomain Count, Query Parameter Count

**Security Flags (Boolean/Counts):**
6. Presence of HTTPS
7. Presence of Direct IP Address
8. Suspicious Keywords (Count & Boolean)
9. URL Shortening Services
10. Punycode Hostname (`xn--`)
11. Double Slash in Path

**Entropy:**
12. Shannon Entropy of Hostname
13. Shannon Entropy of Complete URL

## EXPLAINABLE AI (XAI)
The system includes a post-prediction explanation layer that translates the raw numerical features into human-readable risk factors. When a URL is analyzed, the system returns:
- **Explanation Summary:** A high-level description of why the URL was flagged (or cleared).
- **Risk Factors:** A detailed breakdown of individual suspicious indicators (e.g., `high_entropy`, `missing_https`, `has_ip`), including their extracted value, severity, and a clear explanation of why they increase the risk.

## FEATURE IMPORTANCE & MODEL INTERPRETABILITY
The production Logistic Regression model is highly interpretable. During training, the absolute values of the learned coefficients are extracted and ranked to determine which URL features have the strongest mathematical influence on predictions across the entire dataset.

- **Positive Coefficients:** Indicate features strongly associated with phishing/malware domains.
- **Negative Coefficients:** Indicate features strongly associated with legitimate, safe domains.

*Important: Feature importance indicates mathematical association based on the training data; it does not prove direct causation. For example, a long path does not inherently make a URL malicious, but malware endpoints in the dataset frequently utilize long, complex paths.*

You can view the ranked feature importance JSON by hitting `GET /feature-importance` or checking the **TOP RISK SIGNALS (MODEL INSIGHTS)** panel in the UI.

## PREDICTION HISTORY & PRIVACY
The application maintains a lightweight local prediction history of your recently analyzed URLs (up to a maximum of 50 records). 
- **Privacy First:** This history is stored entirely in your browser's local `localStorage`. The application does not collect user data, IP addresses, or tracking cookies, and does not send history data to any external backend database.
- **Local Control:** You can view your recent analyses directly at the bottom of the dashboard and permanently clear your history with a single click.

## SECURITY ANALYTICS DASHBOARD
A responsive, client-side dashboard provides immediate visual insights into your local threat environment.
- **Local Generation:** All charts, statistics, and risk-signal distribution metrics are calculated locally inside your browser using the stored `localStorage` prediction history. 
- **Privacy Enforcement:** No external analytics tracking, cloud ingestion, or third-party cookies are used. If you clear your local history, the dashboard is safely wiped back to a zero-state instantly.

## SECURITY REPORT GENERATION
Users can generate a downloadable PDF Security Analysis Report for any analyzed URL.
- **Local Generation:** Reports are generated entirely client-side in the browser using jsPDF. The analyzed URL and extracted features are never sent to external PDF generation APIs.
- **Report Contents:** The report includes the final verdict, probability scores, risk factors, explanation summaries, top model signals, and a complete table of the 27 extracted features.
- **Limitations:** The report clearly indicates that it is a static ML-based lexical analysis and does not replace professional dynamic security analysis.

## ADVERSARIAL ROBUSTNESS TESTING
PhishGuard-ML includes a defensive local adversarial testing suite to evaluate model stability against URL manipulation.
- **Offline Synthetic Testing:** The script programmatically applies transformations (subdomain stuffing, long path injections, hyphens, digit packing) to fictional URL strings and measures the drift in prediction probabilities. At no point are any test strings visited or resolved over the network.
- **Model Behavior:** Lexical models map characters to risk vectors. As demonstrated in testing, intentionally injecting extreme anomalies (such as massively long paths containing multiple security keywords) can legitimately push a clean baseline URL over the risk threshold. This is an expected mathematical consequence of purely string-based heuristics rather than a "flaw," highlighting why static analysis must operate in tandem with dynamic threat intel.

## PRODUCTION SECURITY & DEPLOYMENT
PhishGuard-ML is hardened for production environments:
- **Input Validation:** Rejecting empty, non-string, or oversized (> 2048 char) inputs with clean HTTP 400 JSON responses instead of stack traces.
- **Security Headers:** Enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and strict `Content-Security-Policy`.
- **Request Size Limits:** Enforces `MAX_CONTENT_LENGTH` to protect against payload flooding.
- **Rate Limiting:** Implements lightweight in-memory sliding-window request throttling on the `/predict` endpoint to prevent API abuse.
- **Privacy-Safe Logging:** Logs only request metadata (timestamp, endpoint, method, status, duration). Submitted URLs are never persistently logged.
- **Absolute Isolation:** Static URL analysis means the backend purely evaluates strings. It uses zero external requests, DNS lookups, or crawling mechanisms.

*To run in production, ensure `FLASK_ENV=production` is set in your environment variables. This automatically disables debug mode.*

## MODEL COMPARISON & SELECTION
During training, the following machine-learning models were evaluated using a stratified 80/20 split on the 10,000-sample dataset:

| Model | Accuracy | Precision | Recall | F1-score | ROC-AUC |
|-------|----------|-----------|--------|----------|---------|
| **Logistic Regression** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Decision Tree** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Random Forest** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **SVM** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Gradient Boosting** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

**Selected Production Model:** `Logistic Regression`
**Reason for Selection:** All models performed perfectly (1.0000 across all metrics) due to the distinct lexical boundaries between the URLhaus malware endpoints and the Tranco top-level legitimate domains. Because ROC-AUC, F1, and Recall were perfectly tied across all algorithms, **Logistic Regression** was programmatically selected as the production model due to it being the simplest, fastest, and most lightweight algorithm in the evaluation tier. 

*Note: While these benchmark metrics are exceptionally high for this dataset, high benchmark performance does not guarantee 100% real-world detection accuracy. Advanced phishing campaigns increasingly host malicious paths on compromised legitimate domains, which lexical analysis alone cannot always catch.*

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
