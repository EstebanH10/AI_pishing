import pandas as pd
import joblib
import numpy as np
import tldextract
import re
import os
from scipy.sparse import hstack, csr_matrix

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

# Cargar Whitelist Dinámica (Tranco Top 10k)
TRANCO_PATH = "./data/top_1m_tranco.csv"
if os.path.exists(TRANCO_PATH):
    TOP_10K_TRANCO = set(pd.read_csv(TRANCO_PATH)['domain'])
else:
    print(f"[!] Aviso: No se encontró {TRANCO_PATH}. Usando fallback temporal.")
    TOP_10K_TRANCO = {"google.com", "youtube.com", "chatgpt.com", "microsoft.com"}

# Dominios Institucionales/Educativos base (Máxima Confianza)
DOMINIOS_INSTITUCIONALES = {"uniminuto.edu", "instructure.com", "canvaslms.com", "stepbible.org"}

# Proveedores de infraestructura/servicios vitales (Confianza Alta)
PROVEEDORES_CONFIABLES = {"zoom.us", "render.com", "vercel.app", "pages.dev", "myedit.online", "github.com"}

# ==========================================
# 2. FUNCIONES DE APOYO
# ==========================================
def get_tld_risk(url):
    ext = tldextract.extract(url)
    return tld_risk_dict.get(ext.suffix, 0.5)

# ==========================================
# 3. MOTOR DE PREDICCIÓN (PRODUCCIÓN V4)
# ==========================================
def predict_url(url):
    # --- 0. EXTRACCIÓN BÁSICA ---
    ext = tldextract.extract(url)
    dominio_raiz = f"{ext.domain}.{ext.suffix}"
    
    # --- 1. DETERMINAR NIVEL DE CONFIANZA DEL DOMINIO RAÍZ ---
    nivel_confianza = "normal"
    
    if dominio_raiz in TOP_10K_TRANCO or dominio_raiz in PROVEEDORES_CONFIABLES:
        nivel_confianza = "alto"
        
    if ext.suffix == "edu" or ext.suffix == "gov" or dominio_raiz in DOMINIOS_INSTITUCIONALES:
        nivel_confianza = "muy_alto"

    # --- 2. ESCUDO DE SINGLE SIGN-ON (SSO) / OAUTH2 ---
    # Los flujos de login oficiales SIEMPRE se aprueban para no romper accesos
    proveedores_sso = ["login.microsoftonline.com", "accounts.google.com", "appleid.apple.com", "okta.com", "auth0.com", "sso.canvaslms.com"]
    if any(idp in url for idp in proveedores_sso):
        es_oauth = "client_id=" in url and ("redirect_uri=" in url or "redirect=" in url)
        if es_oauth or "SAMLRequest=" in url:
            return "LEGIT (Flujo de Autenticación SSO)", 0.0, -1

    # --- 3. EXTRACCIÓN DE CARACTERÍSTICAS PARA LA IA ---
    tld = ext.suffix
    tld_risk = get_tld_risk(url)
    
    lex = extract_url_features(url)
    adv, marca_detectada = extract_advanced_features(url)
    adv['tld_risk'] = tld_risk 

    # --- 4. PROCESAMIENTO IA ---
    all_features = {**lex, **adv}
    orden_columnas = feature_metadata["lexical"] + feature_metadata["advanced"]
    vector_numerico = [all_features.get(col, 0) for col in orden_columnas]
    
    X_num = pd.DataFrame([vector_numerico], columns=orden_columnas)
    X_num_scaled = scaler.transform(X_num.values) 
    
    X_ngram = vectorizer.transform([url])
    X_final = hstack([csr_matrix(X_num_scaled), X_ngram])
    
    prob = model.predict_proba(X_final)[0][1]

    # --- 5. AJUSTE DINÁMICO DE UMBRALES (HERENCIA DE CONFIANZA) ---
    age = adv.get('domain_age_days', -1)
    brand = adv.get('brand_similarity_score', 0)
    
    keywords_peligrosas = ['swap', 'btc', 'crypto', 'wallet', 'login', 'gouv', 'verify', 'links']
    contiene_keyword = any(kw in url.lower() for kw in keywords_peligrosas)
    es_dominio_numerico = ext.domain.isdigit() 
    
    # Partimos del umbral base
    umbral_bloqueo = threshold_security 
    
    if nivel_confianza == "muy_alto":
        umbral_bloqueo = 0.99 # Extremadamente tolerante (Universidades/Gobierno)
    elif nivel_confianza == "alto":
        umbral_bloqueo = 0.95 # Tolerante a URLs largas (Tranco, Zoom, Apps)
    else:
        # Si es un dominio desconocido ("normal"), somos más agresivos
        if tld_risk > 0.5 or contiene_keyword:
            umbral_bloqueo = min(umbral_bloqueo, 0.60)

    # Excepción Crítica: Open Redirect (El único peligro real en sitios confiables)
    es_open_redirect = any(kw in url.lower() for kw in ['url=http', 'redirect=http', 'return=http', 'goto=http'])
    if nivel_confianza in ["alto", "muy_alto"] and es_open_redirect:
         # Si un sitio confiable redirige hacia afuera, bajamos sus defensas y somos estrictos
         umbral_bloqueo = min(threshold_security * 0.8, 0.60)

    # --- 6. MOTOR DE REGLAS FINALES ---

    # Anomalía absoluta insalvable
    if es_dominio_numerico:
        return "PHISHING (Dominio 100% Numérico)", prob, age

    # Evaluaciones para dominios desconocidos/sospechosos
    if nivel_confianza == "normal":
        # Nubes gratuitas anómalas
        subdomain_providers = ["pages.dev", "vercel.app", "workers.dev", "netlify.app", "github.io", "onrender.com"]
        if any(provider in url for provider in subdomain_providers):
            if ext.subdomain.count('-') >= 2:
                return "PHISHING (Estructura Anómala en Nube Gratuita)", prob, age
            if brand > 0.4:
                return "PHISHING (Suplanta Marca en Nube Gratuita)", prob, age

        # Suplantación de Marca Pura
        if brand >= 0.85:
            return f"PHISHING (Homoglifo Severo de {marca_detectada})", prob, age

        # Dominios nuevos ocultos con keywords
        if (age < 90 or age == -1) and contiene_keyword:
            return "PHISHING (Keyword en Dominio Nuevo/Oculto)", prob, age

    # --- 7. DECISIÓN FINAL IA BASADA EN EL UMBRAL DINÁMICO ---
    if prob >= umbral_bloqueo:
        razon = f"Prob IA: {prob:.2f} > Umbral: {umbral_bloqueo:.2f}"
        if nivel_confianza in ["alto", "muy_alto"]:
             razon = "Sitio Confiable Comprometido (Open Redirect/Anomalía Grave)"
        return f"PHISHING ({razon})", prob, age

    return f"LEGIT (Confianza: {nivel_confianza})", prob, age

# ==========================================
# 4. PRUEBA DE EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore") 
    
    urls = [
        "https://www.youtube.com/",
        "https://app.uniswap.org/",
        "https://chatgpt.com/",
        "https://miaulavirtual.uniminuto.edu/login/canvas", # Prueba de universidad
        "https://login.microsoftonline.com/b1ba85eb-a253-4467/oauth2/v2.0/authorize?client_id=123&redirect_uri=sso.canvas", # Prueba de SSO
        "https://app.zoom.us/wc/84777825246/join?ref_from=launch&uname=ESTEBAN", # Prueba de Zoom (URL profunda)
        "https://app.biblearc.com/project/e56dc4f7-1e1e-4c6e-8852", # Prueba UUID
        "https://myedit.online/es/audio-editor/speech-enhancement",
        "https://unlswap-v3.si/", # Phishing real
        "http://allegro.12881010s-1.biz/", # Phishing real
        "https://login-secure-bancolombia.update-x29.xyz/", # Phishing real bancario
    ]
    
    print(f"\n{'URL':<65} | {'RESULTADO':<45} | {'PROB':<5}")
    print("-" * 125)
    
    for u in urls:
        res, p, dias = predict_url(u)
        print(f"{u[:63]:<65} | {res:<45} | {p:.2f}")