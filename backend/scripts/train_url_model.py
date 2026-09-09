"""
TraceShield URL Threat Intelligence - Scikit-Learn Random Forest Training Script
Extracts 20 lexical/structural features and trains a 100-estimator RandomForestClassifier
on a balanced synthetic dataset of 2,000 URLs (1,000 Phishing vs 1,000 Benign).
Persists the trained model artifact to backend/models/rf_url_model.joblib.
"""

import collections
import ipaddress
import math
import os
import random
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------------------
# Feature Extraction Definitions (20 Lexical / Structural Signals)
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_subdomains",
    "has_ip_address",
    "count_digits",
    "digit_to_letter_ratio",
    "shannon_entropy",
    "is_https",
    "count_params",
    "count_queries",
    "count_slashes",
    "has_punycode",
    "suspicious_tld",
    "suspicious_keyword_count",
    "brand_name_in_subdomain",
    "path_length",
    "hyphen_in_domain",
    "port_present",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "icu",
    "loan", "click", "fit", "rest", "country", "kim", "racing", "download",
    "club", "surf", "monster", "vip", "cam", "bid", "stream", "win", "party",
    "trade", "accountant", "science", "gdn", "date", "faith", "review",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "update", "account", "banking", "secure",
    "confirm", "support", "service", "billing", "auth", "portal", "password",
    "recover", "wallet", "token", "validation", "checkpoint", "security",
    "authenticate", "credential", "suspend", "unlock", "alert", "notice",
    "invoice", "payment", "re-activate", "reactivate",
}

POPULAR_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "chase",
    "wellsfargo", "binance", "coinbase", "meta", "facebook", "instagram",
    "dropbox", "office365", "bankofamerica", "yahoo", "outlook", "adobe",
    "docusign", "citibank", "whatsapp", "telegram", "twitter", "linkedin",
]


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to measure character randomness."""
    if not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_ip_address(host: str) -> int:
    """Checks if host is an IPv4 or IPv6 literal address."""
    if not host:
        return 0
    # Strip port if present
    h = host.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(h)
        return 1
    except ValueError:
        return 0


def extract_url_features(url: str) -> Dict[str, float]:
    """
    Extracts exactly 20 lexical and structural URL features for Machine Learning inference.
    """
    if not isinstance(url, str) or not url.strip():
        url = "http://empty.invalid/"

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://invalid.parse/")

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = (parsed.scheme or "").lower()

    # 1. url_length
    url_length = float(len(url))

    # 2. count_dots
    count_dots = float(url.count("."))

    # 3. count_hyphens
    count_hyphens = float(url.count("-"))

    # 4. count_at
    count_at = float(url.count("@"))

    # 5. count_subdomains
    if host and not is_ip_address(host):
        host_labels = [lbl for lbl in host.split(".") if lbl]
        # e.g., a.b.example.com has 4 labels -> 2 subdomains
        count_subdomains = float(max(0, len(host_labels) - 2))
    else:
        count_subdomains = 0.0

    # 6. has_ip_address
    has_ip = float(is_ip_address(host))

    # 7. count_digits
    digits = sum(c.isdigit() for c in url)
    count_digits = float(digits)

    # 8. digit_to_letter_ratio
    letters = sum(c.isalpha() for c in url)
    digit_to_letter_ratio = float(digits / max(1, letters))

    # 9. shannon_entropy
    shannon_entropy = float(calculate_shannon_entropy(url))

    # 10. is_https
    is_https = 1.0 if scheme == "https" else 0.0

    # 11. count_params
    if query:
        try:
            params = parse_qs(query, keep_blank_values=True)
            count_params = float(len(params))
        except Exception:
            count_params = float(query.count("&") + 1)
    else:
        count_params = 0.0

    # 12. count_queries
    count_queries = float(url.count("?"))

    # 13. count_slashes
    count_slashes = float(url.count("/"))

    # 14. has_punycode
    has_punycode = 1.0 if "xn--" in host else 0.0

    # 15. suspicious_tld
    tld = host.split(".")[-1] if "." in host else ""
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 16. suspicious_keyword_count
    url_lower = url.lower()
    kw_count = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            kw_count += 1
    suspicious_keyword_count = float(kw_count)

    # 17. brand_name_in_subdomain
    brand_in_sub = 0.0
    if host and "." in host and not is_ip_address(host):
        labels = host.split(".")
        if len(labels) > 2:
            subdomain_part = ".".join(labels[:-2])
            for brand in POPULAR_BRANDS:
                if brand in subdomain_part:
                    brand_in_sub = 1.0
                    break
    brand_name_in_subdomain = brand_in_sub

    # 18. path_length
    path_length = float(len(path))

    # 19. hyphen_in_domain
    hyphen_in_domain = 1.0 if "-" in host else 0.0

    # 20. port_present
    port_present = 0.0
    try:
        if parsed.port is not None and parsed.port not in (80, 443):
            port_present = 1.0
    except Exception:
        port_present = 1.0 if re.search(r":\d{2,5}", url) else 0.0

    features = {
        "url_length": url_length,
        "count_dots": count_dots,
        "count_hyphens": count_hyphens,
        "count_at": count_at,
        "count_subdomains": count_subdomains,
        "has_ip_address": has_ip,
        "count_digits": count_digits,
        "digit_to_letter_ratio": digit_to_letter_ratio,
        "shannon_entropy": shannon_entropy,
        "is_https": is_https,
        "count_params": count_params,
        "count_queries": count_queries,
        "count_slashes": count_slashes,
        "has_punycode": has_punycode,
        "suspicious_tld": suspicious_tld,
        "suspicious_keyword_count": suspicious_keyword_count,
        "brand_name_in_subdomain": brand_name_in_subdomain,
        "path_length": path_length,
        "hyphen_in_domain": hyphen_in_domain,
        "port_present": port_present,
    }
    return features


def feature_dict_to_vector(features: Dict[str, float]) -> List[float]:
    """Converts feature dictionary into fixed 20-dimensional float vector."""
    return [features[name] for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Synthetic Dataset Generator (2,000 URLs: 1,000 Phishing vs 1,000 Benign)
# ---------------------------------------------------------------------------

def generate_synthetic_dataset(n_samples: int = 2000, seed: int = 42) -> Tuple[List[str], List[int]]:
    """
    Generates a balanced synthetic dataset of phishing and benign URLs based on standard heuristics.
    """
    random.seed(seed)
    np.random.seed(seed)
    n_each = n_samples // 2

    benign_domains = [
        "google.com", "github.com", "microsoft.com", "amazon.com", "apple.com",
        "wikipedia.org", "cloudflare.com", "stackoverflow.com", "linkedin.com",
        "mozilla.org", "python.org", "nytimes.com", "bbc.co.uk", "cisa.gov",
        "stanford.edu", "mit.edu", "harvard.edu", "salesforce.com", "stripe.com",
        "oracle.com", "ibm.com", "adobe.com", "spotify.com", "dropbox.com",
        "slack.com", "atlassian.net", "zendesk.com", "zoom.us", "shopify.com",
        "medium.com", "reddit.com", "netflix.com", "cnn.com", "nih.gov",
    ]

    benign_paths = [
        "", "/about", "/contact", "/docs/api/v2", "/products/overview",
        "/search", "/articles/2026/03/update", "/downloads/latest", "/help/faq",
        "/pricing", "/solutions/enterprise", "/en-US/docs/Web/JavaScript",
        "/community/forum", "/careers/openings", "/blog/post/how-it-works",
        "/research/papers/2026", "/terms-of-service", "/privacy-policy",
    ]

    benign_params = [
        "", "?q=cloud+computing", "?page=2&sort=desc", "?ref=homepage",
        "?utm_source=newsletter&utm_medium=email", "?lang=en", "?id=1024",
        "?tab=overview&category=tech", "?v=1.4.0",
    ]

    phishing_brands = POPULAR_BRANDS
    phishing_keywords = list(SUSPICIOUS_KEYWORDS)
    phishing_tlds = list(SUSPICIOUS_TLDS)
    phishing_subdomains = [
        "login", "verify-account", "secure-portal", "update-info", "auth-check",
        "banking-online", "wallet-connect", "account-recovery", "support-desk",
        "security-checkpoint", "billing-resolve", "sso-login", "passcode-auth",
    ]

    urls: List[str] = []
    labels: List[int] = []

    # 1. Generate Benign URLs (Label 0)
    for _ in range(n_each):
        dom = random.choice(benign_domains)
        # Subdomains (legitimate)
        if random.random() < 0.35:
            sub = random.choice(["docs", "api", "developer", "blog", "app", "help", "status", "mail", "cdn", "investors"])
            host = f"{sub}.{dom}"
        else:
            host = dom

        scheme = "https" if random.random() < 0.95 else "http"
        path = random.choice(benign_paths)
        if random.random() < 0.4 and path:
            path += f"/item-{random.randint(100, 9999)}"
        param = random.choice(benign_params) if random.random() < 0.45 else ""

        url = f"{scheme}://{host}{path}{param}"
        urls.append(url)
        labels.append(0)

    # 2. Generate Phishing URLs (Label 1)
    for _ in range(n_each):
        p_type = random.choice([
            "brand_subdomain_trap",
            "ip_host_phish",
            "suspicious_tld_combo",
            "punycode_spoof",
            "keyword_stuffed_domain",
            "obfuscated_token_path",
            "port_credential_harvest",
        ])

        scheme = "http" if random.random() < 0.65 else "https"
        brand = random.choice(phishing_brands)
        kw = random.choice(phishing_keywords)
        kw2 = random.choice(phishing_keywords)
        tld = random.choice(phishing_tlds)

        if p_type == "brand_subdomain_trap":
            # e.g., paypal.verify-account.suspicious-domain.xyz
            sub = f"{brand}.{random.choice(phishing_subdomains)}"
            root = f"web-service-{random.randint(10, 99)}.{tld}"
            path = f"/{kw}/{random.randint(100000, 999999)}/index.html"
            query = f"?user={brand}&session_id={random.randint(10000000, 99999999)}&auth_token={random.randint(100000, 999999)}"
            url = f"{scheme}://{sub}.{root}{path}{query}"

        elif p_type == "ip_host_phish":
            # e.g., http://192.168.1.50:8080/secure/login/paypal.php?token=982347923
            ip = f"{random.randint(11, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8443, 8000, 8888, 4443, 9000])}" if random.random() < 0.5 else ""
            path = f"/{brand}/{kw}/{kw2}.php"
            query = f"?id={random.randint(10000, 99999)}&key={random.randint(1000000, 9999999)}"
            url = f"http://{ip}{port}{path}{query}"

        elif p_type == "suspicious_tld_combo":
            # e.g., http://secure-chase-update-account.top/portal/auth
            domain = f"{brand}-{kw}-{random.randint(1, 99)}.{tld}"
            path = f"/{kw2}/confirm-identity"
            query = f"?redirect=https%3A%2F%2F{brand}.com&code={random.randint(1000, 9999)}"
            url = f"{scheme}://{domain}{path}{query}"

        elif p_type == "punycode_spoof":
            # e.g., https://xn--appl-wqa.com/login/verify
            puny_label = f"xn--{brand[:4]}-{random.choice(['wqa', '80a', 'x3a', '52b'])}"
            path = f"/{kw}/account-protection"
            query = f"?attempt={random.randint(1, 5)}"
            url = f"{scheme}://{puny_label}.com{path}{query}"

        elif p_type == "keyword_stuffed_domain":
            # e.g., http://login-verify-account-security-update-center.work/auth
            host = f"{kw}-{kw2}-{brand}-security-online.{tld}"
            path = f"/checkpoint/step/{random.randint(1, 4)}"
            query = f"?uid={random.randint(100000, 999999)}&token={random.randint(10000000, 99999999)}"
            url = f"{scheme}://{host}{path}{query}"

        elif p_type == "obfuscated_token_path":
            # e.g., http://srv-auth-portal.icu/session/v2/secure/@target/account/login.php?client_id=89234
            host = f"srv-{brand}-{kw}.{tld}"
            path = f"/session/v2/{kw}/@admin/{random.randint(1000, 9999)}/{kw2}.html"
            query = f"?token={random.randint(1000000000, 9999999999)}&sig={random.randint(10000, 99999)}&client=web"
            url = f"{scheme}://{host}{path}{query}"

        else:  # port_credential_harvest
            host = f"{brand}-verification-{random.randint(100, 999)}.{tld}"
            port = f":{random.choice([8080, 8443, 8000, 8888, 4443])}"
            path = f"/{kw}/login.asp"
            query = f"?id={random.randint(1000, 9999)}"
            url = f"http://{host}{port}{path}{query}"

        urls.append(url)
        labels.append(1)

    # Shuffle dataset
    combined = list(zip(urls, labels))
    random.shuffle(combined)
    urls, labels = zip(*combined)
    return list(urls), list(labels)


# ---------------------------------------------------------------------------
# Model Training & Serialization
# ---------------------------------------------------------------------------

def train_and_save_model(
    output_path: str = None,
    n_samples: int = 2000,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Trains the Random Forest URL classifier and serializes the model artifact.
    """
    if output_path is None:
        backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        output_path = os.path.join(backend_dir, "models", "rf_url_model.joblib")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print("=" * 70)
    print("TraceShield URL Threat Intelligence - Random Forest Model Training")
    print("=" * 70)
    print(f"[*] Generating {n_samples} balanced synthetic URL samples (1,000 Phishing / 1,000 Benign)...")
    urls, labels = generate_synthetic_dataset(n_samples=n_samples, seed=random_state)

    print(f"[*] Extracting 20 lexical & structural URL features for each sample...")
    X_raw = [feature_dict_to_vector(extract_url_features(u)) for u in urls]
    X = np.array(X_raw, dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=random_state, stratify=y
    )

    print(f"[*] Training RandomForestClassifier(n_estimators=100, random_state={random_state})...")
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=random_state,
        max_depth=15,
        min_samples_split=4,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    print("\n[+] Model Evaluation on Hold-Out Test Set (400 samples):")
    print(f"    - Test Accuracy:  {accuracy * 100:.2f}%")
    print(f"    - Precision:      {precision * 100:.2f}%")
    print(f"    - Recall:         {recall * 100:.2f}%")
    print(f"    - F1-Score:       {f1 * 100:.2f}%")

    print("\n[+] Feature Importances (Top 20 Signals):")
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx, 1):
        print(f"    {rank:2d}. {FEATURE_NAMES[idx]:<26}: {importances[idx] * 100:6.2f}%")

    # Serialize model artifact with metadata
    artifact_payload = {
        "model": clf,
        "feature_names": FEATURE_NAMES,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "n_samples": n_samples,
        "n_estimators": 100,
        "algorithm": "RandomForestClassifier",
    }
    joblib.dump(artifact_payload, output_path, compress=3)
    print(f"\n[+] Successfully saved model artifact to: {output_path}")
    print("=" * 70)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "model_path": output_path,
        "feature_names": FEATURE_NAMES,
    }


if __name__ == "__main__":
    train_and_save_model()
