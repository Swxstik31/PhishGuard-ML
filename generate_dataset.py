import pandas as pd
import random

legit_domains = ["google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com", "apple.com", "microsoft.com", "netflix.com", "github.com", "reddit.com", "yahoo.com", "bing.com", "live.com", "office.com", "zoom.us", "twitch.tv", "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "cnn.com", "nytimes.com", "bbc.com", "espn.com", "weather.com", "zillow.com", "yelp.com"]

phish_keywords = ["login", "verify", "verification", "account", "secure", "update", "password", "banking", "confirm", "signin", "support", "service", "billing", "auth"]
phish_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".info", ".net", ".org"]

urls = []
labels = []

# Generate 500 Legit URLs
for _ in range(500):
    domain = random.choice(legit_domains)
    protocol = random.choice(["https://", "http://"])
    path = random.choice(["", "/", "/about", "/contact", "/home", "/user/profile", "/news", "/help"])
    sub = random.choice(["", "www.", "app.", "mail.", "store."])
    urls.append(f"{protocol}{sub}{domain}{path}")
    labels.append(0)

# Generate 500 Phishing URLs
for _ in range(500):
    kw1 = random.choice(phish_keywords)
    kw2 = random.choice(phish_keywords)
    use_ip = random.random() < 0.2
    
    if use_ip:
        ip = f"{random.randint(11,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        domain = ip
    else:
        domain = f"{kw1}-{kw2}{random.choice(phish_tlds)}"
        
    protocol = random.choice(["http://", "https://"])
    use_subs = random.random() < 0.4
    subs = ""
    if use_subs:
        subs = f"{random.choice(legit_domains)}."
        
    use_at = random.random() < 0.1
    at_str = ""
    if use_at:
        at_str = "support@"
        
    path = f"/{random.choice(phish_keywords)}?id={random.randint(1000,9999)}"
    urls.append(f"{protocol}{at_str}{subs}{domain}{path}")
    labels.append(1)

df = pd.DataFrame({"URL": urls, "label": labels})
df = df.sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv("data/dataset.csv", index=False)
print("Dataset generated with", len(df), "URLs.")
