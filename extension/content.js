chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "BLOCK_PAGE") {
        // Congelamos la página
        document.body.innerHTML = "";
        document.head.innerHTML = "";

        // Creamos la pantalla roja de advertencia
        const warningDiv = document.createElement("div");
        warningDiv.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background-color: #d93025; color: white; z-index: 999999;
            display: flex; flex-direction: column; justify-content: center; align-items: center;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; text-align: center; padding: 20px;
        `;

        warningDiv.innerHTML = `
            <h1 style="font-size: 50px; margin-bottom: 10px;">⚠️ Sitio Engañoso Detectado</h1>
            <p style="font-size: 20px; max-width: 600px;">
                Phishing Shield AI ha bloqueado esta página de manera proactiva. <br><br>
                <strong>Motivo de la IA:</strong> ${request.veredicto} <br>
                <strong>Nivel de Riesgo Matemático:</strong> ${(request.riesgo * 100).toFixed(2)}%
            </p>
            <button id="btnVolver" style="
                margin-top: 30px; padding: 15px 30px; font-size: 18px; font-weight: bold;
                background-color: white; color: #d93025; border: none; border-radius: 5px; cursor: pointer;
            ">Regresar a un lugar seguro</button>
        `;

        document.body.appendChild(warningDiv);

        // Botón para huir de la página
        document.getElementById("btnVolver").addEventListener("click", () => {
            window.history.back();
            // Si no hay historial, mandarlo a Google
            setTimeout(() => { window.location.href = "https://www.google.com"; }, 500);
        });
    }
});