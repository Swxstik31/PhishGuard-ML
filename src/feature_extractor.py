import re
from urllib.parse import urlparse

def extract_features(url):
    """
    Extracts numerical features from a URL for machine learning.
    Returns a dictionary of features in a consistent order.
    """
    features = {}
    
    # URL length
    features['url_length'] = len(url)
    
    # Number of dots
    features['num_dots'] = url.count('.')
    
    # Number of hyphens
    features['num_hyphens'] = url.count('-')
    
    # Number of special characters
    special_chars = set(['@', '?', '=', '&', '%', '_', '/'])
    features['num_special_chars'] = sum(1 for c in url if c in special_chars)
    
    # Presence of @ symbol
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # Presence of an IP address
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    features['has_ip'] = 1 if ip_pattern.search(url) else 0
    
    # Presence of HTTPS
    features['has_https'] = 1 if url.startswith('https://') else 0
    
    # Number of subdomains
    try:
        parsed_url = urlparse(url)
        netloc = parsed_url.netloc
        if not netloc:
            domain_part = url.split('/')[2] if '//' in url else url.split('/')[0]
            features['num_subdomains'] = domain_part.count('.') - 1 if domain_part.count('.') > 0 else 0
        else:
            features['num_subdomains'] = netloc.count('.') - 1 if netloc.count('.') > 0 else 0
    except:
        features['num_subdomains'] = 0
        
    if features['num_subdomains'] < 0:
        features['num_subdomains'] = 0
    
    # Presence of suspicious keywords
    suspicious_keywords = ['login', 'verify', 'verification', 'account', 'secure', 
                           'update', 'password', 'banking', 'confirm', 'signin']
    url_lower = url.lower()
    features['suspicious_keywords_count'] = sum(1 for keyword in suspicious_keywords if keyword in url_lower)
    
    # Whether a known URL-shortening pattern/service is detected
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    features['is_shortened'] = 1 if any(shortener in url_lower for shortener in shorteners) else 0
    
    return features

def get_security_indicators(url):
    """
    Returns human-readable security indicators based on the extracted features.
    """
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
        
    return indicators
