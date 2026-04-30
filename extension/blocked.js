// 1. Leer los datos enviados por background.js
const urlParams = new URLSearchParams(window.location.search);
const tipo = urlParams.get('tipo'); // "WARN" o "BLOCK"
const motivo = urlParams.get('motivo');
const riesgo = urlParams.get('riesgo');
const urlOriginal = urlParams.get('urlOriginal');

// 2. Referencias a los elementos visuales
const titulo = document.getElementById('titulo');
const subtitulo = document.getElementById('subtitulo');
const btnVolver = document.getElementById('btnVolver');

// 3. Cambiar diseño dependiendo de si es Advertencia o Bloqueo
if (tipo === 'WARN') {
    document.body.style.backgroundColor = '#FF9800'; // Naranja
    btnVolver.style.color = '#FF9800';
    titulo.innerText = '🤔 Página Sospechosa';
    subtitulo.innerText = 'Nuestra IA detectó comportamiento inusual. No estamos seguros de que sea un ataque, pero te recomendamos precaución.';
} else {
    document.body.style.backgroundColor = '#d93025'; // Rojo
    btnVolver.style.color = '#d93025';
    titulo.innerText = '🛑 Sitio Engañoso Bloqueado';
    subtitulo.innerText = 'Phishing Shield AI ha bloqueado esta página de manera proactiva por tu seguridad.';
}

// 4. Mostrar los datos de la IA
document.getElementById('motivo').innerText = motivo || "No especificado";
document.getElementById('riesgo').innerText = riesgo ? Number(riesgo).toFixed(2) : "0.00";

// 5. Botón Seguro (Regresar)
btnVolver.addEventListener('click', () => {
    // Intenta retroceder, si no hay historial, manda a Google
    if (window.history.length > 1) {
        window.history.back();
    } else {
        window.location.href = "https://www.google.com";
    }
});

// 6. Botón de Riesgo (Continuar de todos modos)
document.getElementById('btnContinuar').addEventListener('click', () => {
    if (confirm("Si continúas, esta página podría robar tu información personal o contraseñas. ¿Estás absolutamente seguro de que confías en este sitio?")) {
        // Enviar mensaje a background.js para que guarde esta URL en memoria y la deje pasar
        chrome.runtime.sendMessage({ action: "allowUrl", url: urlOriginal });
    }
});