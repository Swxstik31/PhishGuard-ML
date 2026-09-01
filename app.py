import os
import joblib
import pandas as pd
from flask import Flask, request, jsonify, render_template
from src.feature_extractor import extract_features, get_security_indicators

app = Flask(__name__)

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
    print(f"Error loading model: {e}")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    global model, feature_names
    # Try to load model if it wasn't available at startup (e.g. trained after startup)
    if not model or not feature_names:
        try:
            if os.path.exists(model_path):
                model_data = joblib.load(model_path)
                model = model_data['model']
                feature_names = model_data['feature_names']
        except Exception as e:
            pass

    if not model or not feature_names:
        return jsonify({'success': False, 'error': 'Model not found. Please train the model first.'}), 500
        
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'success': False, 'error': 'No URL provided'}), 400
        
    url = data['url'].strip()
    if not url:
        return jsonify({'success': False, 'error': 'URL cannot be empty'}), 400
        
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
            
        indicators = get_security_indicators(url)
        
        print("Received URL:", url)
        print("Extracted features:", features)
        print("Prediction:", risk_score)
        print("Probability:", probability)
        
        return jsonify({
            'success': True,
            'url': url,
            'risk_score': risk_score,
            'phishing_probability': risk_score,
            'verdict': verdict,
            'security_indicators': indicators,
            'extracted_features': features
        })
        
    except Exception as e:
        print("Error during prediction:", e)
        return jsonify({'success': False, 'error': 'Unable to analyze URL'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
