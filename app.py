import os
import json
import time
import logging
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
from src.feature_extractor import extract_features, get_security_indicators

# Initialize basic logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s - %(message)s')
logger = logging.getLogger('phishguard')

app = Flask(__name__)

# Security Configurations
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_CONTENT_LENGTH', 1024 * 50)) # 50KB default
app.config['JSON_SORT_KEYS'] = False
ENV_MODE = os.environ.get('FLASK_ENV', 'production')
app.config['DEBUG'] = (ENV_MODE == 'development')

# Simple In-Memory Rate Limiting
rate_limit_records = {}
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get('RATE_LIMIT', 100))
RATE_LIMIT_WINDOW = 60 # seconds

def is_rate_limited(ip):
    current_time = time.time()
    if ip not in rate_limit_records:
        rate_limit_records[ip] = []
    
    # Filter old requests
    rate_limit_records[ip] = [req_time for req_time in rate_limit_records[ip] if current_time - req_time < RATE_LIMIT_WINDOW]
    
    if len(rate_limit_records[ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return True
        
    rate_limit_records[ip].append(current_time)
    return False

@app.before_request
def start_timer():
    request.start_time = time.time()
    
    # Rate limit check for predict endpoint
    if request.endpoint == 'predict':
        client_ip = request.remote_addr
        if is_rate_limited(client_ip):
            return jsonify({'success': False, 'error': 'Rate limit exceeded. Try again later.'}), 429

@app.after_request
def security_headers(response):
    # Security Headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com;"
    
    # Logging
    duration = time.time() - getattr(request, 'start_time', time.time())
    logger.info(f"{request.method} {request.path} - Status: {response.status_code} - Duration: {duration:.4f}s")
    
    return response

# Centralized Error Handlers
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'success': False, 'error': 'Bad Request'}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({'success': False, 'error': 'Not Found'}), 404

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'success': False, 'error': 'Request entity too large'}), 413

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({'success': False, 'error': 'Too Many Requests'}), 429

@app.errorhandler(500)
def internal_server_error(e):
    return jsonify({'success': False, 'error': 'Internal Server Error'}), 500

base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'model', 'phishing_model.pkl')

model_data = None
model = None
feature_names = None

try:
    if os.path.exists(model_path):
        model_data = joblib.load(model_path)
        model = model_data['model']
        feature_names = model_data['feature_names']
except Exception as e:
    logger.error(f"Error loading model: {e}")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok",
        "model": "available" if model is not None else "unavailable"
    })

@app.route('/feature-importance', methods=['GET'])
def feature_importance():
    importance_path = os.path.join(base_dir, 'model', 'feature_importance.json')
    if os.path.exists(importance_path):
        with open(importance_path, 'r') as f:
            data = json.load(f)
        return jsonify({'success': True, 'feature_importance': data})
    else:
        return jsonify({'success': False, 'error': 'Feature importance data not found'}), 404

@app.route('/predict', methods=['POST'])
def predict():
    global model, feature_names
    if not model or not feature_names:
        try:
            if os.path.exists(model_path):
                model_data = joblib.load(model_path)
                model = model_data['model']
                feature_names = model_data['feature_names']
        except Exception:
            pass

    if not model or not feature_names:
        return jsonify({'success': False, 'error': 'Model not found.'}), 500
        
    try:
        data = request.get_json(silent=True)
    except Exception:
        return jsonify({'success': False, 'error': 'Malformed JSON body.'}), 400
        
    if not data or 'url' not in data:
        return jsonify({'success': False, 'error': 'No URL provided in JSON body.'}), 400
        
    url_input = data['url']
    if not isinstance(url_input, str):
        return jsonify({'success': False, 'error': 'URL must be a string.'}), 400
        
    url = url_input.strip()
    if not url:
        return jsonify({'success': False, 'error': 'URL cannot be empty.'}), 400
        
    if len(url) > 2048:
        return jsonify({'success': False, 'error': 'URL exceeds maximum allowed length (2048 characters).'}), 400
        
    try:
        features = extract_features(url)
        feature_vector = pd.DataFrame([features], columns=feature_names).values
        probability = model.predict_proba(feature_vector)[0][1]
        risk_score = int(probability * 100)
        
        if risk_score <= 30:
            verdict = "LOW RISK"
        elif risk_score <= 70:
            verdict = "SUSPICIOUS"
        else:
            verdict = "HIGH RISK"
            
        factors = []
        if features.get('has_ip') == 1:
            factors.append({"feature": "has_ip", "value": 1, "severity": "high", "explanation": "An IP address is used directly as the hostname instead of a domain name, commonly used to hide malicious server locations."})
        if features.get('has_suspicious_keyword') == 1:
            factors.append({"feature": "suspicious_keyword", "value": 1, "severity": "high", "explanation": "The URL contains a suspicious keyword commonly associated with credential or account verification."})
        if features.get('has_https') == 0:
            factors.append({"feature": "missing_https", "value": 0, "severity": "medium", "explanation": "The connection is unencrypted (HTTP), which may indicate a lack of security standard."})
        if features.get('has_punycode') == 1:
            factors.append({"feature": "punycode", "value": 1, "severity": "high", "explanation": "Punycode (xn--) was detected in the hostname. This is often used in homograph attacks to impersonate legitimate domains."})
        if features.get('is_shortened') == 1:
            factors.append({"feature": "is_shortened", "value": 1, "severity": "high", "explanation": "A URL shortening service was detected, which is frequently used to mask the true destination of phishing links."})
        if features.get('entropy_hostname', 0) > 4.0:
            factors.append({"feature": "high_entropy", "value": round(features.get('entropy_hostname', 0), 2), "severity": "medium", "explanation": "The hostname exhibits high entropy (randomness), which is characteristic of automatically generated malicious domains (DGAs)."})
        if features.get('num_subdomains', 0) > 2:
            factors.append({"feature": "excessive_subdomains", "value": features.get('num_subdomains', 0), "severity": "medium", "explanation": "Multiple subdomains were detected. Attackers use deeply nested subdomains to mimic legitimate sites."})
        if features.get('num_hyphens', 0) > 3:
            factors.append({"feature": "excessive_hyphens", "value": features.get('num_hyphens', 0), "severity": "medium", "explanation": "Multiple hyphens were detected, a common tactic to visually spoof trusted brand names in the URL."})
        if features.get('has_double_slash_in_path') == 1:
            factors.append({"feature": "double_slash", "value": 1, "severity": "medium", "explanation": "A double slash was found in the path portion. This may indicate an attempt to cause an open redirect or mask the actual endpoint."})
        if features.get('url_length', 0) > 75:
            factors.append({"feature": "url_length", "value": features.get('url_length', 0), "severity": "low", "explanation": "The URL is unusually long, which is sometimes used to obscure the actual destination domain."})
        
        if risk_score <= 30:
            if len(factors) == 0:
                summary = "No major suspicious lexical indicators were detected in the submitted URL."
            else:
                summary = "The URL exhibits some minor unusual characteristics, but the overall lexical structure appears low risk."
        elif risk_score <= 70:
            summary = "The URL was classified as suspicious due to the presence of questionable characteristics that warrant further caution."
        else:
            summary = "The URL was classified as high risk because it contains suspicious characteristics strongly associated with phishing structures."

        indicators = get_security_indicators(url)
        
        return jsonify({
            'success': True,
            'url': url,
            'risk_score': risk_score,
            'phishing_probability': risk_score,
            'verdict': verdict,
            'security_indicators': indicators,
            'extracted_features': features,
            'risk_factors': factors,
            'explanation_summary': summary
        })
        
    except Exception as e:
        logger.error(f"Error during prediction: {str(e)}")
        return jsonify({'success': False, 'error': 'Unable to analyze URL.'}), 500

if __name__ == '__main__':
    # Force debug off for explicit production running unless FLASK_ENV dictates it
    app.run(host='0.0.0.0', port=5001, debug=app.config['DEBUG'])
