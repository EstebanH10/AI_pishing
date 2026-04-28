chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId === 0) {
        let currentUrl = details.url;

        if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://") || currentUrl.startsWith("about:")) return;

        try {
            let response = await fetch("http://127.0.0.1:8000/predict", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: currentUrl })
            });

            let data = await response.json();

            if (data.bloquear) {
                // Obtenemos la URL de nuestra página de bloqueo local
                const blockUrl = chrome.runtime.getURL(`blocked.html?motivo=${encodeURIComponent(data.veredicto)}&riesgo=${encodeURIComponent(data.probabilidad_ia * 100)}`);
                
                // Redirigimos la pestaña infractora a nuestra pantalla roja
                chrome.tabs.update(details.tabId, { url: blockUrl });
            }
        } catch (error) {
            console.error("Error contactando IA:", error);
        }
    }
});