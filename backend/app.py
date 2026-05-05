from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from predict import predict_url
import uvicorn
import traceback
import json
import os

app = FastAPI(title="Phishing Shield API")

# Habilitamos CORS para que la extensión de Chrome pueda comunicarse
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- NUEVO: SISTEMA DE ESTADÍSTICAS GLOBALES ---
STATS_FILE = "./data/stats.json"

def load_stats():
    # Si el archivo existe, lo leemos. Si no, creamos los contadores desde cero.
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE, "r") as f:
                return json.load(f)
        except:
            pass
    return {
        "total_enlaces_analizados": 0, 
        "ataques_bloqueados": 0, 
        "advertencias_generadas": 0,
        "sitios_seguros_aprobados": 0
    }

def save_stats(stats):
    # Guardamos los números en el archivo
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f, indent=4)
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
        
        # --- NUEVO: REGISTRAR LA ESTADÍSTICA ---
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

# --- NUEVO: RUTA PARA VER TU REPORTE EN VIVO ---
@app.get("/stats")
async def get_dashboard():
    return load_stats()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)