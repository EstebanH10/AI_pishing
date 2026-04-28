import tldextract
import whois
import datetime
import pandas as pd
import os
import joblib
import re

# -------------------------
# Configuración y Caché
# -------------------------
USE_WHOIS = True # Lo activamos aquí directamente para evitar fallos de referencia
WHOIS_CACHE_PATH = "models/whois_cache.pkl"

os.makedirs("models", exist_ok=True)

if os.path.exists(WHOIS_CACHE_PATH):
    try:
        WHOIS_CACHE = joblib.load(WHOIS_CACHE_PATH)
    except:
        WHOIS_CACHE = {}
else:
    WHOIS_CACHE = {}

# -------------------------
# Cargar Recursos
# -------------------------
from brand_index import load_index
BK_TREE, DOMAIN_SET = load_index(limit=100000)

TLD_RISK_PATH = "./data/tld_risk.csv"
TLD_RISK_MAP = {}
if os.path.exists(TLD_RISK_PATH):
    tld_risk_df = pd.read_csv(TLD_RISK_PATH)
    TLD_RISK_MAP = dict(zip(tld_risk_df["tld"], tld_risk_df["risk_score"]))

# -------------------------
# Funciones de Apoyo
# -------------------------

def extract_domain_parts(url):
    ext = tldextract.extract(url)
    # domain es 'youtube', suffix es 'com'
    return ext.domain.lower(), ext.suffix.lower()

def brand_similarity_features(domain):
    clean_domain = re.sub(r'[^a-zA-Z]', '', domain)
    
    # --- FILTRO 1: Ignorar si el dominio es muy corto ---
    if len(clean_domain) < 4:
        return {"min_brand_distance": 10, "brand_similarity_score": 0.0}, "None"

    matches = BK_TREE.find(clean_domain, 3)
    
    best_brand = "None"
    similarity_score = 0.0
    min_distance = 10

    if matches:
        # Filtramos marcas detectadas que sean demasiado cortas
        valid_matches = [m for m in matches if len(m[1]) > 3]
        
        if valid_matches:
            min_distance, best_brand = min(valid_matches, key=lambda x: x[0])
            
            # --- FILTRO 2: Lógica de Suplantación Reforzada ---
            # Si el dominio es EXACTAMENTE la marca, es seguro
            if best_brand == clean_domain:
                return {"min_brand_distance": 0, "brand_similarity_score": 0.0}, "None"
            
            # Si la marca está ADENTRO pero el dominio tiene basura extra, es Phishing
            if best_brand in clean_domain:
                return {"min_brand_distance": 0, "brand_similarity_score": 1.0}, best_brand
            
            similarity_score = max(0.0, 1.0 - (min_distance / 10.0))

    # Si no hay matches, o si no entró a los IFs anteriores, devuelve esto:
    return {"min_brand_distance": min_distance, "brand_similarity_score": similarity_score}, best_brand
# -------------------------
# 2. Edad del Dominio (WHOIS) - CORRECCIÓN DE TLD
# -------------------------
def domain_age_feature(url):
    import advanced_features
    if not advanced_features.USE_WHOIS:
        return {"domain_age_days": -1, "is_new_domain": 0}

    domain_name, tld_suffix = extract_domain_parts(url)
    
    # IMPORTANTE: Para WHOIS necesitamos 'google.com', no solo 'google'
    full_domain = f"{domain_name}.{tld_suffix}"
    
    if full_domain in WHOIS_CACHE:
        return WHOIS_CACHE[full_domain]

    try:
        print(f"--- Consultando WHOIS para: {full_domain} ---")
        w = whois.whois(full_domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            dates = [d for d in creation_date if isinstance(d, datetime.datetime)]
            creation_date = min(dates) if dates else None

        if creation_date and isinstance(creation_date, datetime.datetime):
            creation_date = creation_date.replace(tzinfo=None)
            now = datetime.datetime.now()
            
            age_days = (now - creation_date).days
            if age_days < 0: age_days = -1
            
            features = {
                "domain_age_days": age_days,
                "is_new_domain": int(0 <= age_days < 90)
            }
            
            WHOIS_CACHE[full_domain] = features
            joblib.dump(WHOIS_CACHE, WHOIS_CACHE_PATH)
            print(f"+++ EXITOSO: {full_domain} guardado ({age_days} días).")
            return features
        else:
            print(f"!!! AVISO: No se obtuvo fecha para {full_domain}")

    except Exception as e:
        print(f"XXX ERROR WHOIS en {full_domain}: {e}")
        pass

    return {"domain_age_days": -1, "is_new_domain": 0}

# -------------------------
# Otras señales
# -------------------------

def tld_risk_feature(tld):
    return {"tld_risk_score": TLD_RISK_MAP.get(tld, 0.5)}

def popularity_feature(domain):
    return {"is_popular_domain": int(domain in DOMAIN_SET)}

def extract_advanced_features(url):
    # Aquí obtenemos 'domain' (ej. google) y 'tld' (ej. com)
    domain, tld = extract_domain_parts(url)
    
    features = {}
    
    # Obtenemos las características de marca y el nombre de la marca detectada
    brand_feats, detected_brand = brand_similarity_features(domain)
    
    features.update(brand_feats)
    features.update(domain_age_feature(url))
    features.update(tld_risk_feature(tld))
    features.update(popularity_feature(domain))
    
    # NUEVAS FEATURES ESTRUCTURALES (Instantáneas)
    # CORRECCIÓN 1: Usamos la variable 'domain' que extrajimos arriba (antes decía ext.domain)
    features["is_numeric_domain"] = 1 if domain.isdigit() else 0
    features["has_deep_path"] = 1 if url.count('/') >= 5 else 0
    features["is_dga_pattern"] = 1 if sum(c.isdigit() or c == '-' for c in domain) >= 3 else 0
    
    # WHOIS Oculto
    features["is_whois_hidden"] = 1 if features.get("domain_age_days", 0) == -1 else 0

    # CORRECCIÓN 2: Retornamos 'detected_brand' (antes decía marca_detectada)
    return features, detected_brand
