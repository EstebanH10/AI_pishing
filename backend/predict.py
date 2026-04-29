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
# (Esto simula el arranque de un servidor)
# ==========================================
model = joblib.load("models/advanced_phishing_model.pkl")
vectorizer = joblib.load("models/ngram_vectorizer.pkl")
feature_metadata = joblib.load("models/feature_metadata.pkl")
threshold_security = joblib.load("models/phishing_threshold.pkl")
scaler = joblib.load("models/scaler.pkl")

# Cargar TLD Risk
tld_risk_df = pd.read_csv("./data/tld_risk.csv")
tld_risk_dict = dict(zip(tld_risk_df['tld'], tld_risk_df['risk_score']))

# --- NUEVO: Cargar Whitelist Dinámica (Tranco Top 10k) ---
TRANCO_PATH = "./data/top_10k_tranco.csv"
if os.path.exists(TRANCO_PATH):
    TOP_10K_TRANCO = set(pd.read_csv(TRANCO_PATH)['domain'])
else:
    print(f"[!] Aviso: No se encontró {TRANCO_PATH}. Usando fallback temporal.")
    TOP_10K_TRANCO = {"google.com", "youtube.com", "chatgpt.com", "microsoft.com"}

# ==========================================
# 2. FUNCIONES DE APOYO
# ==========================================
def get_tld_risk(url):
    ext = tldextract.extract(url)
    return tld_risk_dict.get(ext.suffix, 0.5)

# ==========================================
# 3. MOTOR DE PREDICCIÓN (PRODUCCIÓN)
# ==========================================
def predict_url(url):
    # --- 0. EXTRACCIÓN BÁSICA Y LISTA BLANCA ESTRUCTURADA ---
    ext = tldextract.extract(url)
    dominio_raiz = f"{ext.domain}.{ext.suffix}"
    
    # A. Verificamos si es nuestra propia nube o herramientas de desarrollo vitales
    lista_blanca_desarrollo = {"render.com", "vercel.app", "pages.dev", "github.io"}
    if dominio_raiz in lista_blanca_desarrollo:
        # Solo aprobamos si es la raíz o un subdominio corto, no si tiene guiones raros
        if ext.subdomain.count('-') == 0:
            return "LEGIT (Infraestructura de Desarrollo)", 0.0, -1

    # B. ESCUDO TRANCO TOP 10K (El filtro principal)
    if dominio_raiz in TOP_10K_TRANCO:
        # Micro-filtro de seguridad para evitar ataques de Open Redirect en sitios famosos
        ruta_sospechosa = url.count('/') >= 5
        tiene_redireccion = any(kw in url.lower() for kw in ['redirect', 'url=', 'goto=', 'return='])
        
        if not ruta_sospechosa and not tiene_redireccion:
            # Si es un dominio famoso y su URL se ve normal, lo aprobamos en 1 milisegundo
            return "LEGIT (Tranco Top Global)", 0.0, -1
        # Si tiene parámetros raros, ignoramos el Tranco y dejamos que la IA lo analice abajo

    # --- A. EXTRACCIÓN DE CARACTERÍSTICAS ---
    tld = ext.suffix
    tld_risk = get_tld_risk(url)
    
    lex = extract_url_features(url)
    adv, marca_detectada = extract_advanced_features(url)
    adv['tld_risk'] = tld_risk 

    # --- B. PROCESAMIENTO IA ---
    all_features = {**lex, **adv}
    orden_columnas = feature_metadata["lexical"] + feature_metadata["advanced"]
    vector_numerico = [all_features.get(col, 0) for col in orden_columnas]
    
    # Creamos el DataFrame para alinear nombres, pero pasamos .values al scaler
    X_num = pd.DataFrame([vector_numerico], columns=orden_columnas)
    X_num_scaled = scaler.transform(X_num.values) 
    
    # Vectorizamos el texto y unimos
    X_ngram = vectorizer.transform([url])
    X_final = hstack([csr_matrix(X_num_scaled), X_ngram])
    
    # Obtenemos la probabilidad cruda de la IA
    prob = model.predict_proba(X_final)[0][1]

    # --- C. MOTOR DE REGLAS Y DEFENSA EN PROFUNDIDAD ---
    age = adv.get('domain_age_days', -1)
    brand = adv.get('brand_similarity_score', 0)
    
    # 1. Expandimos palabras clave (Psicología de ataque)
    keywords_peligrosas = ['swap', 'btc', 'crypto', 'wallet', 'login', 'gouv', 'verify', 'links']
    contiene_keyword = any(kw in url.lower() for kw in keywords_peligrosas)

    # 2. Análisis Estructural Profundo
    es_dominio_numerico = ext.domain.isdigit() 
    tiene_numero_largo = bool(re.search(r'\d{10,}', url)) 
    ruta_profunda = url.count('/') >= 5 

    # 3. Umbral dinámico asegurado
    umbral_base = min(threshold_security, 0.75) 
    umbral_estricto = umbral_base * 0.6 if (tld_risk > 0.4 or contiene_keyword) else umbral_base

    # --- REGLAS PRIORIZADAS (NIVEL PRODUCCIÓN V3) ---

    # REGLA 0: ANOMALÍAS ESTRUCTURALES GRAVES
    if es_dominio_numerico:
        return "PHISHING (Dominio 100% Numérico)", prob, age

    # REGLA 1: ESCUDO ESTRUCTURAL PARA NUBES GRATUITAS
    subdomain_providers = ["pages.dev", "vercel.app", "workers.dev", "netlify.app", "github.io", "onrender.com"]
    
    if any(provider in url for provider in subdomain_providers):
        guiones = ext.subdomain.count('-')
        
        # 1. Estructura anómala típica de Phishing (Muchos guiones)
        if guiones >= 2:
            return "PHISHING (Estructura Anómala en Nube Gratuita)", prob, age
            
        # 2. Intento de robar una marca (Damos margen > 0.4 para evitar colisiones raras)
        if brand > 0.4:
            return "PHISHING (Suplanta Marca en Nube Gratuita)", prob, age

    # REGLA 2: ESCUDO INSTITUCIONAL OFICIAL
    if any(suffix in tld for suffix in ["edu", "gov"]):
        if prob > 0.90 and ruta_profunda:
            return "PHISHING (Institución Hackeada)", prob, age
        return "LEGIT (Institución Oficial)", prob, age

    # REGLA 3: SUPLANTACIÓN DE MARCA Y HOMOGLIFOS
    if brand >= 0.85:
        return f"PHISHING (Homoglifo Severo de {marca_detectada})", prob, age
    elif (brand > 0.6 or brand == 1.0) and prob > 0.15: # Bajamos umbral de IA si hay marca
        return f"PHISHING (Suplanta a {marca_detectada})", prob, age

    # REGLA 4: WHITELIST DINÁMICA (Tranco Top 10k)
    # Nota: Estos se analizan con IA por si el sitio Top 10k fue hackeado (Open Redirect)
    if dominio_raiz in TOP_10K_TRANCO:
        if prob > 0.90 and (ruta_profunda or tiene_numero_largo):
            return "PHISHING (Sitio Legítimo Hackeado / Open Redirect)", prob, age
        return "LEGIT (Top Global Tranco)", prob, age

    # REGLA 5: ABUSO DE TRACKERS
    if tiene_numero_largo and ("link" in url.lower() or "click" in url.lower()):
        return "PHISHING (Abuso de Tracker/Redirección)", prob, age

    # REGLA 6: DOMINIOS NUEVOS O CON WHOIS FALLIDO
    if age < 90 or age == -1:
        if contiene_keyword:
            if age != -1 and age < 90: 
                return "PHISHING (Keyword en Dominio Nuevo)", prob, age
            elif age == -1 and prob > 0.20:
                return "PHISHING (Keyword en Dominio Oculto)", prob, age
        
        # Si el TLD es riesgoso y no tenemos edad, confiamos más en la IA
        if tld_risk > 0.6 and prob > 0.25:
             return f"PHISHING (TLD Riesgoso: {tld})", prob, age

    # REGLA 7: DECISIÓN FINAL IA
    if prob >= umbral_estricto:
        return "PHISHING (Detectado por IA)", prob, age

    return "LEGIT (Evaluación Limpia)", prob, age

# ==========================================
# 4. PRUEBA DE EJECUCIÓN
# ==========================================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore") # Limpia cualquier warning residual
    
    urls = [
        "https://www.youtube.com/",
        "https://unlswap-v3.si/",
        "https://app.uniswap.org/",
        "https://chatgpt.com/",
        "http://allegro.12881010s-1.biz/",
        "http://pyruvylnfusarial.info",
        "https://app.campanha-brasil.click/contato/fisica",
        "https://gemini.google.com/app/8739db2d7432c637?hl=es",
        "https://www.stepbible.org/?q=version=LBLA",
        "https://odontoclinicasmr.com/",
        "https://btc089.77768.cc/#/",
        "https://cpam-gouvfr.com/",
        "http://meritking-1697.com",
        "https://www.verifypof.us/",
        "https://login.bakewarestorage.com/cmhnkaod",
        "https://links.truthsocial.com/link/116176749744825965",
        "https://ln.run/ZzJig",
        "https://shopy.com.pk/ssy/web/ali/",
        "https://mondrelay.maa-rasa.co/index.php",
        "https://www.pmal-cadastro.online/",
        "https://sura-enlinea.co/",
        "https://eufutureweb.info/AOVr0RWO.html",
        "https://my.harver.com/app/landing/6758650591aacc0012a41bdd/login?fbclid=IwAR7i05g4tGuDYe5qllZKvks_wBcQ-GjAf4O0rJoLzhrvj8GDRatsPoGCJyTvEQ_wapm_MzQ2MWQ1OGEtMzkwOS00NzlkLWE3M2MtN2M1YjhlYjhlNDQ2_waaem_BxBb0-icjbBJyCctAeLSIg",
        # --- PRUEBAS AVANZADAS ---
        "https://www.googIe.com", # Homoglifo (i mayúscula en vez de L)
        "https://login-secure-bancolombia.update-x29.xyz/", # Subdominio abusivo
    ]
    
    print(f"\n{'URL':<50} | {'RESULTADO':<35} | {'PROB':<6} | {'EDAD'}")
    print("-" * 110)
    
    for u in urls:
        res, p, dias = predict_url(u)
        edad_str = f"{dias} días" if dias != -1 else "Desconocida"
        print(f"{u[:48]:<50} | {res:<35} | {p:.4f} | {edad_str}")