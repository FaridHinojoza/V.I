/* Utilidades compartidas del frontend V.I (sin innerHTML: solo textContent). */
(function () {
  "use strict";

  var TOKEN_KEY = "vi_jwt_token";

  /* ---- Validación del lado cliente (defensa en profundidad; el servidor revalida) ---- */

  // Operadores NoSQL ($ne, $gt, $where, ...) y objetos JSON con prefijo $.
  var NOSQL_RE = /\$(?:ne|eq|gt|gte|lt|lte|in|nin|not|nor|or|and|where|regex|exists|expr|function)\b|\{\s*["']\$/i;
  // Patrones típicos de inyección SQL.
  var SQLI_RE = /['"]\s*(?:or|and)\s*['"\d]|['"]\s*=\s*['"]|\b1\s*=\s*1\b|;\s*--|\/\*|\*\/|;\s*(?:drop|select|insert|update|delete)\b|\bunion\s+(?:all\s+)?select\b|\bdrop\s+(?:table|database)\b/i;
  // XSS: etiquetas, manejadores de eventos (onerror, onload, ...) y URIs javascript:.
  var XSS_RE = /[<>]|<script|onerror\s*=|onload\s*=|\bon[a-z]{2,20}\s*=|(?:javascript|vbscript)\s*:|data\s*:\s*text\/html/i;
  var CONTROL_RE = /[\x00-\x1f\x7f]/;

  var USUARIO_RE = /^[A-Za-z0-9_.-]{2,50}$/;
  var EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,54}\.[A-Za-z]{2,24}$/;
  var CODIGO_RE = /^[0-9]{6}$/;

  function hasUnsafeContent(value, allowLeadingDollar) {
    if (CONTROL_RE.test(value)) { return true; }
    if (!allowLeadingDollar && value.replace(/^\s+/, "").charAt(0) === "$") { return true; }
    return NOSQL_RE.test(value) || SQLI_RE.test(value) || XSS_RE.test(value);
  }

  function validateUsuario(value) {
    if (value === "") { return "El usuario es obligatorio."; }
    if (hasUnsafeContent(value, false)) { return "El usuario contiene caracteres no permitidos."; }
    if (!USUARIO_RE.test(value)) { return "Use de 2 a 50 caracteres: letras, números, punto, guion o guion bajo."; }
    return "";
  }

  function validatePassword(value, minChars) {
    if (value === "" || value.trim() === "") { return "La contraseña es obligatoria."; }
    if (hasUnsafeContent(value, true)) { return "La contraseña contiene caracteres o patrones no permitidos."; }
    if (value.length < minChars) { return "La contraseña debe tener al menos " + minChars + " caracteres."; }
    if (new TextEncoder().encode(value).length > 72) { return "La contraseña no debe superar los 72 bytes."; }
    return "";
  }

  function validateEmail(value) {
    if (value === "") { return "El correo electrónico es obligatorio."; }
    if (hasUnsafeContent(value, false)) { return "El correo contiene caracteres no permitidos."; }
    if (value.length > 120 || value.indexOf("..") !== -1 || !EMAIL_RE.test(value)) {
      return "Ingrese un correo electrónico válido.";
    }
    return "";
  }

  function validateCodigo(value) {
    if (!CODIGO_RE.test(value)) { return "El código debe contener exactamente 6 dígitos."; }
    return "";
  }

  /* ---- Sesión: solo sessionStorage ---- */

  function getToken() {
    try { return window.sessionStorage.getItem(TOKEN_KEY); } catch (e) { return null; }
  }
  function setToken(token) {
    try { window.sessionStorage.setItem(TOKEN_KEY, token); } catch (e) { /* ignorado */ }
  }
  function clearToken() {
    try { window.sessionStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignorado */ }
  }

  /* ---- Red ---- */

  function postJson(url, payload) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        return { ok: response.ok, status: response.status, data: data };
      });
    });
  }

  /* ---- DOM seguro ---- */

  function byId(id) { return document.getElementById(id); }

  function showFieldError(inputId, message) {
    var input = byId(inputId);
    var holder = byId(inputId + "-error");
    if (input) { input.setAttribute("aria-invalid", message ? "true" : "false"); }
    if (holder) {
      holder.textContent = message || "";
      holder.hidden = !message;
    }
  }

  function showAlert(prefix, title, text) {
    var box = byId(prefix + "-alert");
    if (!box) { return; }
    if (title !== null && title !== undefined) { byId(prefix + "-alert-title").textContent = title; }
    if (text !== null && text !== undefined) { byId(prefix + "-alert-text").textContent = text; }
    box.hidden = false;
  }

  function hideAlert(prefix) {
    var box = byId(prefix + "-alert");
    if (box) { box.hidden = true; }
  }

  function setupPasswordToggles() {
    var buttons = document.querySelectorAll("[data-toggle-password]");
    Array.prototype.forEach.call(buttons, function (button) {
      button.addEventListener("click", function () {
        var input = byId(button.getAttribute("data-toggle-password"));
        if (!input) { return; }
        var showing = input.getAttribute("type") === "text";
        input.setAttribute("type", showing ? "password" : "text");
        button.textContent = showing ? "Mostrar" : "Ocultar";
      });
    });
  }

  window.VI = {
    TOKEN_KEY: TOKEN_KEY,
    validateUsuario: validateUsuario,
    validatePassword: validatePassword,
    validateEmail: validateEmail,
    validateCodigo: validateCodigo,
    getToken: getToken,
    setToken: setToken,
    clearToken: clearToken,
    postJson: postJson,
    byId: byId,
    showFieldError: showFieldError,
    showAlert: showAlert,
    hideAlert: hideAlert
  };

  document.addEventListener("DOMContentLoaded", setupPasswordToggles);
})();
