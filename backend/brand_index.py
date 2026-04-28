import pandas as pd
import tldextract
import pybktree
import Levenshtein
import os
import joblib

TOP_DOMAINS_PATH = "data/top_domains.csv"
BK_TREE_PATH = "models/bktree.pkl"
DOMAIN_SET_PATH = "models/domain_set.pkl"

def extract_base_domain(domain):
    ext = tldextract.extract(domain)
    return ext.domain.lower()

def build_index(limit=100000):
    print("Construyendo índice de marcas (incluyendo marcas críticas)...")
    
    # 1. Cargar dominios del dataset top_domains
    if os.path.exists(TOP_DOMAINS_PATH):
        df = pd.read_csv(TOP_DOMAINS_PATH)
        domains = [extract_base_domain(d) for d in df["Domain"][:limit]]
    else:
        domains = []

    # 2. FORZAR MARCAS CRÍTICAS (Garantiza que siempre estén protegidas)
    critical_brands = [
        "uniswap", "metamask", "binance", "coinbase", "pancakeswap", 
        "phantom", "paypal", "netflix", "microsoft", "apple", "google", "chatgpt"
    ]
    domains.extend(critical_brands)

    # Limpiar duplicados y vacíos
    domains = list(set(filter(None, domains)))

    # 3. Crear el árbol de búsqueda por similitud (BK-Tree)
    tree = pybktree.BKTree(Levenshtein.distance, domains)

    if not os.path.exists("models"):
        os.makedirs("models")
    
    joblib.dump(tree, BK_TREE_PATH)
    joblib.dump(set(domains), DOMAIN_SET_PATH)

    print(f"Índice guardado con {len(domains)} marcas únicas.")
    return tree, set(domains)

def load_index(limit=100000):
    if os.path.exists(BK_TREE_PATH) and os.path.exists(DOMAIN_SET_PATH):
        return joblib.load(BK_TREE_PATH), joblib.load(DOMAIN_SET_PATH)
    else:
        return build_index(limit)