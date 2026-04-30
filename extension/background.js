// MEMORIA TEMPORAL: Guardamos las URLs que el usuario decide perdonar
const userAllowedUrls = new Set();

// Escuchar los clics en el botón de "Continuar" desde la pantalla de bloqueo
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "allowUrl") {
        userAllowedUrls.add(message.url); // Lo guardamos en memoria
        chrome.tabs.update(sender.tab.id, { url: message.url }); // Recargamos la página original
    }
});

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId === 0) {
        let currentUrl = details.url;

        if (currentUrl.startsWith("chrome://") || currentUrl.startsWith("chrome-extension://") || currentUrl.startsWith("about:")) return;

        // Si el usuario ya perdonó esta URL, dejamos pasar directamente
        if (userAllowedUrls.has(currentUrl)) return;

        try {
            let tab = await chrome.tabs.get(details.tabId).catch(() => ({ url: "" }));
            let origenUrl = tab.url || "";

            let response = await fetch("https://ai-pishing.onrender.com/predict", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ 
                    url: currentUrl,
                    origen: origenUrl
                })
            });

            let data = await response.json();

            // Si la IA decide que es una Advertencia (WARN) o un Bloqueo (BLOCK)
            if (data.accion === "BLOCK" || data.accion === "WARN") {
                // Pasamos todos los datos importantes por la URL a blocked.html
                const blockUrl = chrome.runtime.getURL(
                    `blocked.html?tipo=${data.accion}&motivo=${encodeURIComponent(data.veredicto)}&riesgo=${encodeURIComponent(data.probabilidad_ia * 100)}&urlOriginal=${encodeURIComponent(currentUrl)}`
                );
                chrome.tabs.update(details.tabId, { url: blockUrl });
            }
        } catch (error) {
            console.error("Error contactando IA:", error);
        }
    }
});