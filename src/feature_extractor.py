import re
import math
from urllib.parse import urlparse, parse_qs

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_features(url):
    features = {}
    url_lower = url.lower()
    
    # ---------------------------
    # EXISTING 10 FEATURES
    # ---------------------------
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    
    special_chars = set(['@', '?', '=', '&', '%', '_', '/'])
    features['num_special_chars'] = sum(1 for c in url if c in special_chars)
    
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0
    features['has_https'] = 1 if url_lower.startswith('https://') else 0
    
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc
    if not netloc:
        domain_part = url.split('/')[2] if '//' in url else url.split('/')[0]
        features['num_subdomains'] = max(0, domain_part.count('.') - 1)
    else:
        features['num_subdomains'] = max(0, netloc.count('.') - 1)
        
    suspicious_keywords = ['login', 'verify', 'verification', 'account', 'secure', 
                           'update', 'password', 'banking', 'confirm', 'signin']
    features['suspicious_keywords_count'] = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    features['is_shortened'] = 1 if any(shortener in url_lower for shortener in shorteners) else 0
    
    # ---------------------------
    # NEW EXTENDED FEATURES
    # ---------------------------
    hostname = netloc if netloc else (url.split('/')[2] if '//' in url else url.split('/')[0])
    features['domain_length'] = len(hostname)
    features['path_length'] = len(parsed_url.path)
    features['query_length'] = len(parsed_url.query)
    
    num_digits = sum(c.isdigit() for c in url)
    features['num_digits'] = num_digits
    features['num_slashes'] = url.count('/')
    
    # Query params length (keys in query)
    features['num_query_params'] = len(parse_qs(parsed_url.query)) if parsed_url.query else 0
    
    features['num_equals'] = url.count('=')
    features['num_ampersands'] = url.count('&')
    features['num_percents'] = url.count('%')
    features['num_at_chars'] = url.count('@')
    features['num_underscores'] = url.count('_')
    
    features['has_suspicious_keyword'] = 1 if features['suspicious_keywords_count'] > 0 else 0
    features['has_punycode'] = 1 if 'xn--' in hostname.lower() else 0
    
    # Double slash in path (excluding protocol)
    path_and_query = url[url.find('//')+2:] if '//' in url else url
    path_and_query = path_and_query[path_and_query.find('/'):] if '/' in path_and_query else ""
    features['has_double_slash_in_path'] = 1 if '//' in path_and_query else 0
    
    features['entropy_hostname'] = shannon_entropy(hostname)
    features['entropy_url'] = shannon_entropy(url)
    features['ratio_digits'] = num_digits / len(url) if len(url) > 0 else 0
    
    return features

def get_security_indicators(url):
    indicators = []
    features = extract_features(url)
    
    if features['has_https'] == 0:
        indicators.append("⚠ HTTPS is not enabled")
    else:
        indicators.append("✓ HTTPS is enabled")
        
    if features['suspicious_keywords_count'] > 0:
        indicators.append("⚠ Suspicious keyword detected")
        
    if features['has_ip'] == 1:
        indicators.append("⚠ IP address used instead of normal domain")
        
    if features['url_length'] > 75:
        indicators.append("⚠ Unusually long URL")
        
    if features['num_subdomains'] > 2:
        indicators.append("⚠ Multiple subdomains detected")
        
    if features['has_at_symbol'] == 1:
        indicators.append("⚠ URL contains @ symbol")
        
    if features['num_hyphens'] > 3:
        indicators.append("⚠ Multiple hyphens detected in URL")
        
    if features['is_shortened'] == 1:
        indicators.append("⚠ URL shortening service detected")
        
    if features['has_punycode'] == 1:
        indicators.append("⚠ Punycode domain detected")
        
    if features['has_double_slash_in_path'] == 1:
        indicators.append("⚠ Double slash in URL path")
        
    return indicators
