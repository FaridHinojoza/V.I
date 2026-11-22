/* Pantalla 3 — Registro directo de usuario (Figuras 12 y 13, US-11 / RF-17). */
(function () {
  "use strict";

  var form = VI.byId("registro-form");
  var submit = VI.byId("registro-submit");

  function serverErrorDetail(res) {
    if (res.status === 409) {
      return typeof res.data.detail === "string"
        ? res.data.detail
        : "El usuario o correo electrónico ya se encuentra registrado.";
    }
    if (res.status === 400 && typeof res.data.detail === "string") {
      return res.data.detail;
    }
    if (res.status === 422) {
      return "Verifique el formato de los datos ingresados e intente nuevamente.";
    }
    return "No fue posible registrar el usuario en este momento. Intente más tarde.";
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    VI.hideAlert("registro");

    var usuario = VI.byId("usuario").value;
    var correo = VI.byId("correo").value;
    var clave = VI.byId("clave").value;
    var confirmar = VI.byId("confirmar-clave").value;

    var usuarioError = VI.validateUsuario(usuario);
    var correoError = VI.validateEmail(correo);
    var claveError = VI.validatePassword(clave, 8);
    var confirmarError = VI.validatePassword(confirmar, 8);
    if (!confirmarError && clave !== confirmar) {
      confirmarError = "Las contraseñas no coinciden.";
    }

    VI.showFieldError("usuario", usuarioError);
    VI.showFieldError("correo", correoError);
    VI.showFieldError("clave", claveError);
    VI.showFieldError("confirmar-clave", confirmarError);
    if (usuarioError || correoError || claveError || confirmarError) {
      return;
    }

    submit.disabled = true;
    VI.postJson("/api/auth/registro", {
      usuario: usuario,
      correo: correo,
      clave: clave,
      confirmar_clave: confirmar
    })
      .then(function (res) {
        if (res.ok && res.status === 201) {
          window.location.assign("/login?registrado=1");
          return;
        }
        VI.showAlert(
          "registro",
          "No se pudo completar el registro de usuario.",
          serverErrorDetail(res)
        );
      })
      .catch(function () {
        VI.showAlert(
          "registro",
          "Sin conexión con el servidor.",
          "Verifique su red e intente nuevamente."
        );
      })
      .then(function () {
        submit.disabled = false;
      });
  });
})();
