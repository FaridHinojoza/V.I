/* Pantalla 1 — Inicio de sesión única (Figuras 8 y 9). */
(function () {
  "use strict";

  var form = VI.byId("login-form");
  var submit = VI.byId("login-submit");

  // Si ya hay una sesión válida en esta pestaña, ir directo al monitoreo.
  var existing = VI.getToken();
  if (existing) {
    fetch("/api/auth/verificar", { headers: { "Authorization": "Bearer " + existing } })
      .then(function (r) { if (r.ok) { window.location.replace("/monitoreo"); } else { VI.clearToken(); } })
      .catch(function () { /* sin red: permanecer en login */ });
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    VI.hideAlert("login");

    var usuario = VI.byId("usuario").value;
    var clave = VI.byId("clave").value;

    var usuarioError = VI.validateUsuario(usuario);
    var claveError = VI.validatePassword(clave, 1);
    VI.showFieldError("usuario", usuarioError);
    VI.showFieldError("clave", claveError);
    if (usuarioError || claveError) { return; }

    submit.disabled = true;
    VI.postJson("/api/auth/login", { usuario: usuario, clave: clave })
      .then(function (res) {
        if (res.ok && res.data && typeof res.data.token === "string") {
          VI.setToken(res.data.token);
          window.location.assign("/monitoreo");
          return;
        }
        if (res.status === 401) {
          // Texto exacto de la Figura 9 (el servidor devuelve el mismo en "detail").
          VI.showAlert(
            "login",
            typeof res.data.detail === "string" ? res.data.detail : "Credenciales inválidas o sesión única ya activa.",
            "Verifique su usuario y contraseña e intente nuevamente."
          );
        } else if (res.status === 422) {
          VI.showAlert("login", "Datos de acceso no válidos.", "Revise los caracteres ingresados e intente nuevamente.");
        } else {
          VI.showAlert("login", "Servicio no disponible.", "No fue posible iniciar sesión en este momento. Intente más tarde.");
        }
      })
      .catch(function () {
        VI.showAlert("login", "Sin conexión con el servidor.", "Verifique su red e intente nuevamente.");
      })
      .then(function () { submit.disabled = false; });
  });
})();
