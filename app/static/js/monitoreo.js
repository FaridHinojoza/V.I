/* Pantalla 3 (base) — Monitoreo en Vivo: guardia de sesión y cierre de sesión (Figura 12). */
(function () {
  "use strict";

  var token = VI.getToken();

  function goToLogin() {
    VI.clearToken();
    window.location.replace("/login");
  }

  function releaseSession(currentToken) {
    // keepalive permite que la petición sobreviva al cierre de la pestaña.
    return fetch("/api/auth/logout", {
      method: "POST",
      headers: { "Authorization": "Bearer " + currentToken },
      keepalive: true
    });
  }

  // Guardia: sin JWT válido y activo en el servidor, volver a /login.
  if (!token) {
    goToLogin();
    return;
  }

  fetch("/api/auth/verificar", { headers: { "Authorization": "Bearer " + token } })
    .then(function (res) { if (!res.ok) { goToLogin(); } })
    .catch(function () { /* sin red: se mantiene la vista; el servidor sigue validando */ });

  VI.byId("logout-button").addEventListener("click", function () {
    var current = VI.getToken();
    VI.clearToken();
    if (!current) { window.location.replace("/login"); return; }
    releaseSession(current)
      .catch(function () { /* la sesión expira igualmente por JWT */ })
      .then(function () { window.location.replace("/login"); });
  });

  // Cerrar la pestaña o el navegador libera la sesión única en el servidor.
  window.addEventListener("pagehide", function () {
    var current = VI.getToken();
    if (current) {
      releaseSession(current);
      VI.clearToken();
    }
  });

  // Controles de umbrales: solo reflejan el valor en pantalla (la lógica llega en US-06/US-07).
  var etiquetasTrayectoria = { "1": "Baja", "2": "Media", "3": "Alta" };
  VI.byId("umbral-tiempo").addEventListener("input", function (event) {
    VI.byId("umbral-tiempo-valor").textContent = event.target.value + " s";
  });
  VI.byId("umbral-trayectoria").addEventListener("input", function (event) {
    VI.byId("umbral-trayectoria-valor").textContent = etiquetasTrayectoria[event.target.value] || "Media";
  });
})();
