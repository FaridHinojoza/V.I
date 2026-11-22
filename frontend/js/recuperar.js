/* Pantalla 2 — Recuperación de contraseña en dos pasos (Figuras 10 y 11). */
(function () {
  "use strict";

  var paso1 = VI.byId("paso-1");
  var paso2 = VI.byId("paso-2");
  var correoActual = "";

  function goToStep(step) {
    var second = step === 2;
    paso1.hidden = second;
    paso2.hidden = !second;
    VI.byId("step-indicator-1").className = second ? "step" : "step step-active";
    VI.byId("step-indicator-2").className = second ? "step step-active" : "step";
    if (second) {
      VI.byId("step-indicator-2").setAttribute("aria-current", "step");
      VI.byId("step-indicator-1").removeAttribute("aria-current");
    } else {
      VI.byId("step-indicator-1").setAttribute("aria-current", "step");
      VI.byId("step-indicator-2").removeAttribute("aria-current");
    }
  }

  function serverMessage(res, fallbackTitle) {
    if (res.status === 404) { return "El correo electrónico no se encuentra registrado."; }
    if (res.status === 422) { return "Los datos ingresados no son válidos."; }
    if (res.status === 502) { return "No se pudo enviar el código por correo electrónico."; }
    if (res.status === 400 && typeof res.data.detail === "string") { return res.data.detail; }
    return fallbackTitle;
  }

  function solicitarCodigo(button, onSuccess) {
    VI.hideAlert("paso1");
    var correo = VI.byId("correo").value;
    var correoError = VI.validateEmail(correo);
    VI.showFieldError("correo", correoError);
    if (correoError) { return; }

    button.disabled = true;
    VI.postJson("/api/auth/recuperar", { accion: "solicitar_codigo", correo: correo })
      .then(function (res) {
        if (res.ok) {
          correoActual = correo;
          VI.byId("correo-destino").textContent = correo;
          onSuccess();
        } else {
          VI.showAlert("paso1", "No se pudo enviar el código.", serverMessage(res, "Intente nuevamente en unos minutos."));
        }
      })
      .catch(function () { VI.showAlert("paso1", "Sin conexión con el servidor.", "Verifique su red e intente nuevamente."); })
      .then(function () { button.disabled = false; });
  }

  paso1.addEventListener("submit", function (event) {
    event.preventDefault();
    solicitarCodigo(VI.byId("paso1-submit"), function () { goToStep(2); });
  });

  VI.byId("reenviar-codigo").addEventListener("click", function () {
    var button = VI.byId("reenviar-codigo");
    VI.hideAlert("paso2");
    button.disabled = true;
    VI.postJson("/api/auth/recuperar", { accion: "solicitar_codigo", correo: correoActual })
      .then(function (res) {
        if (res.ok) {
          VI.showFieldError("codigo", "");
          VI.byId("paso2-aviso-title").firstChild.textContent = "Código reenviado al correo ";
        } else {
          VI.showAlert("paso2", "No se pudo reenviar el código.", serverMessage(res, "Intente nuevamente en unos minutos."));
        }
      })
      .catch(function () { VI.showAlert("paso2", "Sin conexión con el servidor.", "Verifique su red e intente nuevamente."); })
      .then(function () { button.disabled = false; });
  });

  paso2.addEventListener("submit", function (event) {
    event.preventDefault();
    VI.hideAlert("paso2");

    var codigo = VI.byId("codigo").value;
    var nueva = VI.byId("nueva-clave").value;
    var confirmar = VI.byId("confirmar-clave").value;

    var codigoError = VI.validateCodigo(codigo);
    var nuevaError = VI.validatePassword(nueva, 8);
    var confirmarError = VI.validatePassword(confirmar, 8);
    if (!nuevaError && !confirmarError && nueva !== confirmar) {
      confirmarError = "Ambas contraseñas deben coincidir.";
    }
    VI.showFieldError("codigo", codigoError);
    VI.showFieldError("nueva-clave", nuevaError);
    VI.showFieldError("confirmar-clave", confirmarError);
    if (codigoError || nuevaError || confirmarError) { return; }

    var button = VI.byId("paso2-submit");
    button.disabled = true;
    VI.postJson("/api/auth/recuperar", {
      accion: "actualizar_clave",
      correo: correoActual,
      codigo: codigo,
      nueva_clave: nueva,
      confirmar_clave: confirmar
    })
      .then(function (res) {
        if (res.ok) {
          VI.clearToken();
          window.location.assign("/login");
        } else {
          VI.showAlert("paso2", "No se pudo actualizar la contraseña.", serverMessage(res, "Verifique los datos e intente nuevamente."));
        }
      })
      .catch(function () { VI.showAlert("paso2", "Sin conexión con el servidor.", "Verifique su red e intente nuevamente."); })
      .then(function () { button.disabled = false; });
  });
})();
