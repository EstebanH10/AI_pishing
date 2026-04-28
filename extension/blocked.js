document.addEventListener("DOMContentLoaded", () => {
    // Leemos los motivos de la URL que mandó el background.js
    const urlParams = new URLSearchParams(window.location.search);
    
    const motivo = urlParams.get('motivo') || "Desconocido (Bloqueo Preventivo)";
    const riesgoRaw = urlParams.get('riesgo');

    // Imprimimos el motivo
    document.getElementById("motivo").innerText = motivo;

    // Imprimimos el riesgo asegurándonos de que sea un número válido
    if (riesgoRaw && !isNaN(riesgoRaw)) {
        document.getElementById("riesgo").innerText = parseFloat(riesgoRaw).toFixed(2);
    } else {
        document.getElementById("riesgo").innerText = "100.00";
    }

    // Botón de escape
    document.getElementById("btnVolver").addEventListener("click", () => {
        window.location.href = "https://www.google.com";
    });
});