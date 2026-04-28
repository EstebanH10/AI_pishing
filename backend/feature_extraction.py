import math
import re
from collections import Counter
from urllib.parse import urlparse

# -----------------------------
# Helpers
# -----------------------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def char_ratio(s: str, condition) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if condition(c)) / len(s)

# -----------------------------
# Feature extractor (LISTA-FREE)
# -----------------------------
def extract_url_features(url: str) -> dict:
    url = url.lower()
    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    labels = domain.split(".")
    tld = labels[-1] if labels else ""

    features = {}

    # -------------------------
    # Longitudes
    # -------------------------
    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["query_length"] = len(query)

    # -------------------------
    # Estructura
    # -------------------------
    features["num_dots"] = domain.count(".")
    features["num_hyphens"] = domain.count("-")
    features["num_underscores"] = domain.count("_")
    features["num_subdomains"] = max(len(labels) - 2, 0)

    features["path_depth"] = path.count("/")
    features["query_params"] = query.count("&") + (1 if query else 0)

    # -------------------------
    # SEÑALES DE ALERTA PHISHING (NUEVO)
    # -------------------------
    # 1. Uso de credenciales falsas en la URL (muy raro en sitios legitimos)
    features["qty_at_symbol"] = url.count("@")
    
    # 2. Redirecciones ocultas (esperamos 1 por el http://, si hay más, es sospechoso)
    features["qty_double_slash"] = url.count("//") 
    
    # 3. Palabras clave explícitas (Psicología del atacante)
    keywords = ['login', 'secure', 'account', 'update', 'verify', 'wallet', 'auth', 'billing', 'support', 'recovery']
    features["suspicious_keywords"] = sum(1 for kw in keywords if kw in url)

    # -------------------------
    # Distribución de caracteres
    # -------------------------
    features["digit_ratio"] = char_ratio(domain, str.isdigit)
    features["alpha_ratio"] = char_ratio(domain, str.isalpha)
    features["non_alnum_ratio"] = char_ratio(domain, lambda c: not c.isalnum())

    # -------------------------
    # Entropía (MUY importante)
    # -------------------------
    features["domain_entropy"] = shannon_entropy(domain)
    features["path_entropy"] = shannon_entropy(path)

    # -------------------------
    # Vocales vs consonantes
    # -------------------------
    vowels = sum(c in "aeiou" for c in domain)
    consonants = sum(c.isalpha() and c not in "aeiou" for c in domain)
    features["vowel_ratio"] = vowels / (consonants + 1)

    # -------------------------
    # Labels del dominio
    # -------------------------
    features["max_label_length"] = max(len(l) for l in labels) if labels else 0
    features["avg_label_length"] = (
        sum(len(l) for l in labels) / len(labels)
        if labels else 0
    )

    # -------------------------
    # Proxies de rareza
    # -------------------------
    features["long_label_ratio"] = sum(len(l) > 10 for l in labels) / (len(labels) + 1)
    features["digit_label_ratio"] = sum(any(c.isdigit() for c in l) for l in labels) / (len(labels) + 1)

    # -------------------------
    # Esquema
    # -------------------------
    features["has_https"] = int(parsed.scheme == "https")
    features["has_ip"] = int(bool(re.search(r"\d+\.\d+\.\d+\.\d+", domain)))

    return features