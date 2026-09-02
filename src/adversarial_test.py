import os
import json
import joblib
import pandas as pd
from feature_extractor import extract_features

def apply_transformations(url):
    transformations = []
    
    # 1. Base
    transformations.append({"name": "base", "url": url})
    
    # 2. Add subdomain
    if "://" in url:
        parts = url.split("://")
        transformations.append({"name": "add_subdomain", "url": f"{parts[0]}://sub.{parts[1]}"})
    
    # 3. HTTP to HTTPS / HTTPS to HTTP
    if url.startswith("http://"):
        transformations.append({"name": "change_to_https", "url": url.replace("http://", "https://", 1)})
    elif url.startswith("https://"):
        transformations.append({"name": "change_to_http", "url": url.replace("https://", "http://", 1)})
        
    # 4. Add long harmless path
    if url.endswith("/"):
        transformations.append({"name": "add_long_path", "url": url + "auth/verify/user/session/login"})
    else:
        transformations.append({"name": "add_long_path", "url": url + "/auth/verify/user/session/login"})
        
    # 5. Add digits
    transformations.append({"name": "add_digits", "url": url + "?id=123456789"})
    
    # 6. Add hyphens
    if "://" in url:
        parts = url.split("://")
        host_path = parts[1].split("/", 1)
        host = host_path[0]
        if "." in host:
            host_parts = host.split(".")
            host_parts[0] = host_parts[0] + "-test-node"
            new_host = ".".join(host_parts)
            if len(host_path) > 1:
                transformations.append({"name": "add_hyphens", "url": f"{parts[0]}://{new_host}/{host_path[1]}"})
            else:
                transformations.append({"name": "add_hyphens", "url": f"{parts[0]}://{new_host}"})
                
    # 7. Add special chars
    transformations.append({"name": "add_special_chars", "url": url + "?token=a@b!c#d$"})
    
    # 8. Add suspicious keywords
    transformations.append({"name": "add_suspicious_keywords", "url": url + "?secure=update&password=confirm&account=verify"})
    
    # 9. Add dots
    if "://" in url:
        parts = url.split("://")
        transformations.append({"name": "add_dots", "url": f"{parts[0]}://a.b.c.d.e.{parts[1]}"})

    return transformations

def calculate_risk(model_obj, url):
    model = model_obj['model']
    feature_names = model_obj['feature_names']
    
    features = extract_features(url)
    features_df = pd.DataFrame([features], columns=feature_names)
    
    # Predict using probability
    prob = model.predict_proba(features_df)[0][1]
    risk_score = round(prob * 100)
    
    if risk_score >= 70:
        verdict = "HIGH RISK"
    elif risk_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"
        
    return prob, risk_score, verdict

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path = os.path.join(base_dir, 'model', 'phishing_model.pkl')
    json_report_path = os.path.join(base_dir, 'model', 'model_robustness_report.json')
    md_report_path = os.path.join(base_dir, 'model', 'model_robustness_report.md')
    
    if not os.path.exists(model_path):
        print(f"Model not found at {model_path}")
        return
        
    model_obj = joblib.load(model_path)
    
    test_urls = [
        "http://example.com/login",
        "https://www.example.com",
        "http://secure-login-verify-example.com/account/login",
        "http://192.0.2.10/login"
    ]
    
    results = []
    verdict_changes = 0
    total_prob_change = 0
    max_prob_change = 0
    
    print("Starting adversarial robustness testing...")
    
    for base_url in test_urls:
        transforms = apply_transformations(base_url)
        
        # Original
        orig = next(t for t in transforms if t["name"] == "base")
        orig_prob, orig_score, orig_verdict = calculate_risk(model_obj, orig["url"])
        
        for t in transforms:
            if t["name"] == "base":
                continue
                
            t_prob, t_score, t_verdict = calculate_risk(model_obj, t["url"])
            
            prob_diff = abs(t_prob - orig_prob)
            total_prob_change += prob_diff
            if prob_diff > max_prob_change:
                max_prob_change = prob_diff
                
            if t_verdict != orig_verdict:
                verdict_changes += 1
                
            results.append({
                "original_url": orig["url"],
                "transformed_url": t["url"],
                "transformation_applied": t["name"],
                "original_phishing_probability": round(orig_prob, 4),
                "transformed_phishing_probability": round(t_prob, 4),
                "original_risk_score": orig_score,
                "transformed_risk_score": t_score,
                "original_verdict": orig_verdict,
                "transformed_verdict": t_verdict
            })
            
    num_test_cases = len(results)
    avg_prob_change = total_prob_change / num_test_cases if num_test_cases > 0 else 0
    stability = 100 - (verdict_changes / num_test_cases * 100) if num_test_cases > 0 else 100
    
    summary = {
        "metrics": {
            "number_of_test_cases": num_test_cases,
            "prediction_stability": f"{round(stability, 2)}%",
            "average_probability_change": round(avg_prob_change, 4),
            "maximum_probability_change": round(max_prob_change, 4),
            "number_of_verdict_changes": verdict_changes
        },
        "test_cases": results
    }
    
    os.makedirs(os.path.dirname(json_report_path), exist_ok=True)
    with open(json_report_path, 'w') as f:
        json.dump(summary, f, indent=4)
        
    md_content = f"""# PhishGuard-ML Adversarial Robustness Report
    
## Evaluation Metrics
- **Number of Test Cases:** {num_test_cases}
- **Prediction Stability (Unchanged Verdicts):** {round(stability, 2)}%
- **Average Probability Change:** {round(avg_prob_change, 4)}
- **Maximum Probability Change:** {round(max_prob_change, 4)}
- **Number of Verdict Changes:** {verdict_changes}

## Summary
The adversarial robustness test evaluates how the Logistic Regression model reacts to synthetic URL transformations. 
A change in prediction does not necessarily mean the model is "wrong" - lexical models mathematically map strings to risk boundaries, so adding suspicious keywords or excessive dots naturally forces the string into a higher-risk vector.

This test operates completely offline using fictional test URLs and does not connect to any network.

## Transformation Details
"""
    for r in results:
        md_content += f"""
### {r['transformation_applied'].upper()}
- **Original:** `{r['original_url']}` ({r['original_verdict']}, {r['original_risk_score']}%)
- **Transformed:** `{r['transformed_url']}` ({r['transformed_verdict']}, {r['transformed_risk_score']}%)
"""
    
    with open(md_report_path, 'w') as f:
        f.write(md_content)
        
    print(f"Testing complete. Stability: {round(stability, 2)}%")
    print(f"Reports saved to {json_report_path} and {md_report_path}")

if __name__ == "__main__":
    main()
