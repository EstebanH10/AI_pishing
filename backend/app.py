from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from predict import predict_url
import uvicorn
import traceback
import requests # <--- NUEVO: Necesario para hablar con JSONBin
import json

app = FastAPI(title="Phishing Shield API")

# Habilitamos CORS para que la extensión de Chrome pueda comunicarse
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- NUEVO: SISTEMA DE ESTADÍSTICAS PERSISTENTES EN LA NUBE ---
BIN_ID = "6a07b18c250b1311c35830c6"
API_KEY = "$2a$10$vyStvDvrN.aomDsI93GRQu3P8HIQibijfb0/ZnuiXRe1Rx.X0NTeG"

JSONBIN_URL = f"https://api.jsonbin.io/v3/b/{BIN_ID}"

# Estos headers envían tu llave secreta en cada petición
HEADERS = {
    'X-Master-Key': API_KEY,
    'Content-Type': 'application/json'
}

def load_stats():
    # Leemos los datos directamente desde la nube
    try:
        req = requests.get(JSONBIN_URL, headers=HEADERS)
        if req.status_code == 200:
            return req.json()['record']
    except Exception as e:
        print(f"Error leyendo estadísticas de la nube: {e}")
        
    # Fallback si falla el internet o las credenciales
    return {
        "total_enlaces_analizados": 0, 
        "ataques_bloqueados": 0, 
        "advertencias_generadas": 0,
        "sitios_seguros_aprobados": 0
    }

def save_stats(stats):
    # Usamos PUT para sobreescribir el archivo en la nube con los nuevos números
    try:
        requests.put(JSONBIN_URL, json=stats, headers=HEADERS)
    except Exception as e:
        print(f"Error guardando estadísticas en la nube: {e}")
# -----------------------------------------------

class URLRequest(BaseModel):
    url: str
    origen: Optional[str] = None

class PredictionResponse(BaseModel):
    url: str
    veredicto: str
    probabilidad_ia: float
    accion: str

@app.post("/predict", response_model=PredictionResponse)
async def analyze_url(request: URLRequest):
    if request.url.startswith("chrome://") or request.url.startswith("edge://") or request.url.startswith("about:") or request.url.startswith("chrome-extension://"):
        return {"url": request.url, "veredicto": "Local/Ignorada", "probabilidad_ia": 0.0, "accion": "ALLOW"}

    try:
        resultado, prob, edad, accion = predict_url(request.url, request.origen) 
        
        # --- REGISTRAR LA ESTADÍSTICA ---
        stats = load_stats()
        stats["total_enlaces_analizados"] += 1
        
        if accion == "BLOCK":
            stats["ataques_bloqueados"] += 1
        elif accion == "WARN":
            stats["advertencias_generadas"] += 1
        elif accion == "ALLOW":
            stats["sitios_seguros_aprobados"] += 1
            
        save_stats(stats)
        # ---------------------------------------

        return {
            "url": request.url,
            "veredicto": resultado,
            "probabilidad_ia": round(float(prob), 4),
            "accion": accion
        }
    except Exception as e:
        print("\n❌ --- ERROR FATAL DETECTADO ---")
        traceback.print_exc()
        print("--------------------------------\n")
        raise HTTPException(status_code=500, detail=str(e))

# --- RUTA PARA VER TU REPORTE EN VIVO ---
@app.get("/stats")
async def get_dashboard():
    return load_stats()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)