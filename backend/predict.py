import pandas as pd
import joblib
import numpy as np
import tldextract
import re
import os
from urllib.parse import urlparse # NUEVO: Importante para limpiar el tracking
from scipy.sparse import hstack, csr_matrix

import warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Importamos tus extractores
from feature_extraction import extract_url_features
from advanced_features import extract_advanced_features

# ==========================================
# 1. CARGA DE MODELOS Y RECURSOS EN MEMORIA
# ==========================================
model = joblib.load("models/advanced_phishing_model.pkl")
vectorizer = joblib.load("models/ngram_vectorizer.pkl")
feature_metadata = joblib.load("models/feature_metadata.pkl")
threshold_security = joblib.load("models/phishing_threshold.pkl")
scaler = joblib.load("models/scaler.pkl")

# Cargar TLD Risk
tld_risk_df = pd.read_csv("./data/tld_risk.csv")
tld_risk_dict = dict(zip(tld_risk_df['tld'], tld_risk_df['risk_score']))

# Cargar Whitelist Dinámica (Tranco)
TRANCO_PATH = "./data/top_1m_tranco.csv"
if os.path.exists(TRANCO_PATH):
    df_tranco = pd.read_csv(TRANCO_PATH, header=None, names=['rank', 'domain'])
    TOP_10K_TRANCO = set(df_tranco.head(100000)['domain'])
else:
    TOP_10K_TRANCO = {"google.com", "youtube.com", "chatgpt.com", "microsoft.com"}

# ==========================================
# 2. FUNCIONES DE APOYO
# ==========================================
def get_tld_risk(url):
    ext = tldextract.extract(url)
    return tld_risk_dict.get(ext.suffix, 0.5)

# ==========================================
# 3. MOTOR DE PREDICCIÓN (PRODUCCIÓN - ESTABLE)
# ==========================================
def predict_url(url, origen=None):
    ext = tldextract.extract(url)
    dominio_raiz = f"{ext.domain}.{ext.suffix}"
    
    # --- 1. HERENCIA DE CONFIANZA POR ORIGEN ---
    if origen and origen != "":
        ext_origen = tldextract.extract(origen)
        dominio_origen = f"{ext_origen.domain}.{ext_origen.suffix}"
        
        if dominio_raiz == dominio_origen:
            es_open_redirect_interno = any(kw in url.lower() for kw in ['url=http', 'redirect=http', 'return=http', 'goto=http'])
            if not es_open_redirect_interno:
                return "LEGIT (Navegación Interna Segura)", 0.0, -1, "ALLOW"

    # --- 2. EVALUACIÓN DE DOMINIO (PRE-IA) ---
    tld_risk = get_tld_risk(url)
    
    # Extraemos características que solo dependen del dominio (Edad y Marca)
    adv, marca_detectada = extract_advanced_features(url)
    adv['tld_risk'] = tld_risk 
    age = adv.get('domain_age_days', -1)
    brand = adv.get('brand_similarity_score', 0)

    # --- 3. FLUJO OAUTH / SSO ESTRUCTURAL ---
    es_oauth_estructural = "client_id=" in url and ("redirect_uri=" in url or "redirect=" in url)
    if es_oauth_estructural or "SAMLRequest=" in url:
        if "redirect_uri=http://" not in url:
            return "LEGIT (Flujo de Autenticación SSO)", 0.0, age, "ALLOW"

    # --- 4. MOTOR DE REPUTACIÓN Y UMBRAL DINÁMICO ---
    umbral_bloqueo = threshold_security 
    nivel_confianza = "normal"

    # CORRECCIÓN INSTITUCIONAL: Abarca .edu.co, .gov.mx, etc usando "in" en lugar de "=="
    es_institucional = "edu" in ext.suffix or "gov" in ext.suffix or "mil" in ext.suffix

    nubes_gratuitas = ["pages.dev", "vercel.app", "workers.dev", "netlify.app", "github.io", "onrender.com", "firebaseapp.com", "sites.google.com"]
    es_nube_gratuita = any(provider in dominio_raiz for provider in nubes_gratuitas)
    es_open_redirect = any(kw in url.lower() for kw in ['url=http', 'redirect=http', 'return=http', 'goto=http'])

    if (age > 365 or dominio_raiz in TOP_10K_TRANCO or es_institucional) and not es_nube_gratuita and brand < 0.5:
        nivel_confianza = "alto"
        umbral_bloqueo = 0.98 
        
        if es_institucional or age > 1095:
            nivel_confianza = "muy_alto"
            umbral_bloqueo = 0.995 # Casi intocable
            
    elif (0 < age < 60) or tld_risk > 0.6:
        umbral_bloqueo = min(umbral_bloqueo, 0.60) 
        nivel_confianza = "bajo"

    if nivel_confianza in ["alto", "muy_alto"] and es_open_redirect:
         umbral_bloqueo = min(threshold_security * 0.8, 0.65)

    # --- 5. NORMALIZACIÓN DE RUIDO (LA SOLUCIÓN AL TRACKING) ---
    url_para_ia = url
    # Si es un dominio de alta confianza y no hay redirección, la longitud loca es marketing/tracking.
    # Limpiamos los parámetros (todo después del '?') para no asustar a la Inteligencia Artificial.
    if nivel_confianza in ["alto", "muy_alto"] and not es_open_redirect:
        parsed = urlparse(url)
        url_para_ia = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
    # --- 6. EXTRACCIÓN LÉXICA Y MATEMÁTICAS ---
    # Usamos la URL normalizada para extraer características y vectorizar
    lex = extract_url_features(url_para_ia) 
    
    all_features = {**lex, **adv}
    orden_columnas = feature_metadata["lexical"] + feature_metadata["advanced"]
    vector_numerico = [all_features.get(col, 0) for col in orden_columnas]
    
    X_num = pd.DataFrame([vector_numerico], columns=orden_columnas)
    X_num_scaled = scaler.transform(X_num.values) 
    
    X_ngram = vectorizer.transform([url_para_ia]) # Pasamos la URL limpia al modelo
    X_final = hstack([csr_matrix(X_num_scaled), X_ngram])
    
    prob = model.predict_proba(X_final)[0][1]

    # --- 7. DEFINICIÓN DE DOBLE UMBRAL ---
    umbral_advertencia = umbral_bloqueo * 0.85 

    # --- 8. REGLAS FINALES ESTRUCTURALES ---
    if es_nube_gratuita:
        if ext.subdomain.count('-') >= 2:
            return "PHISHING (Estructura Anómala en Nube Gratuita)", prob, age, "BLOCK"
        if brand > 0.4:
            return "PHISHING (Suplanta Marca en Nube Gratuita)", prob, age, "BLOCK"

    if ext.domain.isdigit():
        return "PHISHING (Dominio 100% Numérico)", prob, age, "BLOCK"

    if brand >= 0.85 and nivel_confianza != "muy_alto":
        return f"PHISHING (Homoglifo Severo de {marca_detectada})", prob, age, "BLOCK"

    # --- 9. DECISIÓN FINAL IA ---
    if prob >= umbral_bloqueo:
        razon = "Dominio Establecido pero URL Crítica" if nivel_confianza in ["alto", "muy_alto"] else "Detectado por IA"
        return f"PHISHING ({razon})", prob, age, "BLOCK"
        
    elif prob >= umbral_advertencia:
        return f"SOSPECHOSO (Comportamiento inusual detectado)", prob, age, "WARN"

    return f"LEGIT (Confianza: {nivel_confianza})", prob, age, "ALLOW"