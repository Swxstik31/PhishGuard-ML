# PhishGuard-ML Adversarial Robustness Report
    
## Evaluation Metrics
- **Number of Test Cases:** 32
- **Prediction Stability (Unchanged Verdicts):** 93.75%
- **Average Probability Change:** 0.0515
- **Maximum Probability Change:** 0.9996
- **Number of Verdict Changes:** 2

## Summary
The adversarial robustness test evaluates how the Logistic Regression model reacts to synthetic URL transformations. 
A change in prediction does not necessarily mean the model is "wrong" - lexical models mathematically map strings to risk boundaries, so adding suspicious keywords or excessive dots naturally forces the string into a higher-risk vector.

This test operates completely offline using fictional test URLs and does not connect to any network.

## Transformation Details

### ADD_SUBDOMAIN
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://sub.example.com/login` (HIGH RISK, 100%)

### CHANGE_TO_HTTPS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `https://example.com/login` (HIGH RISK, 99%)

### ADD_LONG_PATH
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://example.com/login/auth/verify/user/session/login` (HIGH RISK, 100%)

### ADD_DIGITS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://example.com/login?id=123456789` (HIGH RISK, 100%)

### ADD_HYPHENS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://example-test-node.com/login` (HIGH RISK, 100%)

### ADD_SPECIAL_CHARS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://example.com/login?token=a@b!c#d$` (HIGH RISK, 100%)

### ADD_SUSPICIOUS_KEYWORDS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://example.com/login?secure=update&password=confirm&account=verify` (HIGH RISK, 100%)

### ADD_DOTS
- **Original:** `http://example.com/login` (HIGH RISK, 100%)
- **Transformed:** `http://a.b.c.d.e.example.com/login` (HIGH RISK, 100%)

### ADD_SUBDOMAIN
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://sub.www.example.com` (LOW RISK, 0%)

### CHANGE_TO_HTTP
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `http://www.example.com` (LOW RISK, 0%)

### ADD_LONG_PATH
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://www.example.com/auth/verify/user/session/login` (HIGH RISK, 100%)

### ADD_DIGITS
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://www.example.com?id=123456789` (SUSPICIOUS, 62%)

### ADD_HYPHENS
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://www-test-node.example.com` (LOW RISK, 0%)

### ADD_SPECIAL_CHARS
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://www.example.com?token=a@b!c#d$` (LOW RISK, 0%)

### ADD_SUSPICIOUS_KEYWORDS
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://www.example.com?secure=update&password=confirm&account=verify` (LOW RISK, 1%)

### ADD_DOTS
- **Original:** `https://www.example.com` (LOW RISK, 0%)
- **Transformed:** `https://a.b.c.d.e.www.example.com` (LOW RISK, 0%)

### ADD_SUBDOMAIN
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://sub.secure-login-verify-example.com/account/login` (HIGH RISK, 100%)

### CHANGE_TO_HTTPS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `https://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)

### ADD_LONG_PATH
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://secure-login-verify-example.com/account/login/auth/verify/user/session/login` (HIGH RISK, 100%)

### ADD_DIGITS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://secure-login-verify-example.com/account/login?id=123456789` (HIGH RISK, 100%)

### ADD_HYPHENS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://secure-login-verify-example-test-node.com/account/login` (HIGH RISK, 100%)

### ADD_SPECIAL_CHARS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://secure-login-verify-example.com/account/login?token=a@b!c#d$` (HIGH RISK, 100%)

### ADD_SUSPICIOUS_KEYWORDS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://secure-login-verify-example.com/account/login?secure=update&password=confirm&account=verify` (HIGH RISK, 100%)

### ADD_DOTS
- **Original:** `http://secure-login-verify-example.com/account/login` (HIGH RISK, 100%)
- **Transformed:** `http://a.b.c.d.e.secure-login-verify-example.com/account/login` (HIGH RISK, 100%)

### ADD_SUBDOMAIN
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://sub.192.0.2.10/login` (HIGH RISK, 100%)

### CHANGE_TO_HTTPS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `https://192.0.2.10/login` (HIGH RISK, 100%)

### ADD_LONG_PATH
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://192.0.2.10/login/auth/verify/user/session/login` (HIGH RISK, 100%)

### ADD_DIGITS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://192.0.2.10/login?id=123456789` (HIGH RISK, 100%)

### ADD_HYPHENS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://192-test-node.0.2.10/login` (HIGH RISK, 100%)

### ADD_SPECIAL_CHARS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://192.0.2.10/login?token=a@b!c#d$` (HIGH RISK, 100%)

### ADD_SUSPICIOUS_KEYWORDS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://192.0.2.10/login?secure=update&password=confirm&account=verify` (HIGH RISK, 100%)

### ADD_DOTS
- **Original:** `http://192.0.2.10/login` (HIGH RISK, 100%)
- **Transformed:** `http://a.b.c.d.e.192.0.2.10/login` (HIGH RISK, 100%)
