from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from predict import predict_url
import uvicorn
import traceback

app = FastAPI(title="Phishing Shield API")

# Habilitamos CORS para que la extensión de Chrome pueda comunicarse
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    veredicto: str
    probabilidad_ia: float
    bloquear: bool

@app.post("/predict", response_model=PredictionResponse)
async def analyze_url(request: URLRequest):
    # Filtramos URLs internas del navegador para no gastar recursos
    if request.url.startswith("chrome://") or request.url.startswith("edge://") or request.url.startswith("about:") or request.url.startswith("chrome-extension://"):
        return {"url": request.url, "veredicto": "Local/Ignorada", "probabilidad_ia": 0.0, "bloquear": False}

    try:
        resultado, prob, edad = predict_url(request.url)
        return {
            "url": request.url,
            "veredicto": resultado,
            "probabilidad_ia": round(float(prob), 4),
            "bloquear": "PHISHING" in resultado
        }
    except Exception as e:
        print("\n❌ --- ERROR FATAL DETECTADO ---")
        traceback.print_exc() # <--- NUEVO: Esto imprimirá la línea exacta del error en tu terminal
        print("--------------------------------\n")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    # Arrancamos el servidor en el puerto 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)