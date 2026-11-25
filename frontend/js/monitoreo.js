/* Pantalla 3 — Monitoreo en Vivo (US-02 / US-03 / US-04 / RF-03 a RF-07 / RNF-01 / CP-02 a CP-04).
 * Orquesta el acceso dual a cámara en vivo: Cámara Local (PC vía WebRTC/getUserMedia)
 * o Enlace de Cámara en Red (RTSP / IP vía WebSocket /ws/monitoreo), junto con la detección
 * de peatones con YOLO en CPU y la telemetría operativa.
 */
(function () {
  "use strict";

  var token = VI.getToken();
  var mediaStream = null;
  var socket = null;
  var origenSeleccionado = "local"; // "local" | "rtsp"
  var rtspActivo = false;
  var rtspConectando = false;

  // Estado de Detección de Peatones con YOLO en CPU y RAM (US-04 / RF-07 / RNF-01)
  var deteccionesActivas = [];
  var esperandoDeteccion = false;
  var timerDeteccionCPU = null;
  var captureCanvas = document.createElement("canvas");
  var captureCtx = captureCanvas ? captureCanvas.getContext("2d") : null;

  // Elementos del DOM
  var btnModoLocal = VI.byId("modo-camara-local");
  var btnModoRtsp = VI.byId("modo-camara-rtsp");
  var filaConfigRtsp = VI.byId("rtsp-config-row");
  var inputRtspUrl = VI.byId("rtsp-url-input");
  var btnIniciarCamara = VI.byId("iniciar-camara");
  var badgeEstadoCamara = VI.byId("camara-estado");
  var cercoStatusHint = VI.byId("cerco-status-hint");
  var videoElement = VI.byId("video-stream");
  var rtspImgElement = VI.byId("rtsp-stream");
  var canvasElement = VI.byId("canvas-stage");
  var placeholderStage = VI.byId("stage-placeholder");
  var placeholderText = VI.byId("stage-placeholder-text");

  var ESQUEMA_CAMARA_RE = /^(?:rtsp|rtsps|http|https):\/\/[^\s<>]+$/i;

  function goToLogin() {
    VI.clearToken();
    window.location.replace("/login");
  }

  function releaseSession(currentToken) {
    return fetch("/api/auth/logout", {
      method: "POST",
      headers: { "Authorization": "Bearer " + currentToken },
      keepalive: true
    });
  }

  if (!token) {
    goToLogin();
    return;
  }

  fetch("/api/auth/verificar", { headers: { "Authorization": "Bearer " + token } })
    .then(function (res) { if (!res.ok) { goToLogin(); } })
    .catch(function () { /* Intermitencia de red tolerada */ });

  function estaCamaraActiva() {
    return Boolean((mediaStream && mediaStream.active) || rtspActivo);
  }

  function enviarMensajeWS(payload) {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(payload));
    }
  }

  function actualizarMetricasDOM(metricas) {
    if (!metricas) { return; }
    var metricNodes = document.querySelectorAll(".metric-value");
    if (metricNodes.length < 6) { return; }
    if (metricas.fps !== undefined) { metricNodes[0].textContent = Number(metricas.fps).toFixed(1) + " FPS"; }
    if (metricas.inferencia_ms !== undefined) { metricNodes[1].textContent = Number(metricas.inferencia_ms).toFixed(1) + " ms"; }
    if (metricas.area_cerco_pct !== undefined) { metricNodes[2].textContent = Number(metricas.area_cerco_pct).toFixed(1) + " %"; }
    if (metricas.cpu_pct !== undefined) { metricNodes[3].textContent = Number(metricas.cpu_pct).toFixed(1) + " %"; }
    if (metricas.ram_mb !== undefined) { metricNodes[4].textContent = Number(metricas.ram_mb).toFixed(0) + " MB"; }
    if (metricas.peatones !== undefined && metricas.alertas !== undefined) {
      metricNodes[5].textContent = metricas.peatones + " / " + metricas.alertas;
    }
  }

  function actualizarMetricaArea(porcentaje) {
    var metricNodes = document.querySelectorAll(".metric-value");
    if (metricNodes.length >= 3 && porcentaje !== undefined) {
      metricNodes[2].textContent = Number(porcentaje).toFixed(1) + " %";
    }
  }

  function reiniciarMetricasDOM() {
    var metricNodes = document.querySelectorAll(".metric-value");
    if (metricNodes.length < 6) { return; }
    metricNodes[0].textContent = "-- FPS";
    metricNodes[1].textContent = "-- ms";
    metricNodes[2].textContent = "-- %";
    metricNodes[3].textContent = "-- %";
    metricNodes[4].textContent = "-- MB";
    metricNodes[5].textContent = "0 / 0";
  }

  var cercoCtrl = window.VICerco.crearControladorCerco({
    canvasElement: canvasElement,
    btnDibujarCerco: VI.byId("dibujar-cerco"),
    btnCerrarCerco: VI.byId("cerrar-cerco"),
    btnEditarCerco: VI.byId("editar-cerco"),
    btnLimpiarCerco: VI.byId("limpiar-cerco"),
    cercoVerticesBadge: VI.byId("cerco-vertices-badge"),
    cercoStatusHint: cercoStatusHint,
    estaCamaraActiva: estaCamaraActiva,
    enviarMensajeWS: enviarMensajeWS,
    alActualizarArea: actualizarMetricaArea,
    alLimpiarDetecciones: function () {
      deteccionesActivas = [];
      esperandoDeteccion = false;
      actualizarMetricasDOM({ peatones: 0, alertas: 0 });
    }
  });

  // ---------------------------------------------------------------------------
  // Captura de Fotogramas de Cámara Local con Backpressure hacia YOLO en CPU (US-04)
  // ---------------------------------------------------------------------------
  function capturarYEnviarFrameCerco() {
    if (esperandoDeteccion) { return; }
    if (!mediaStream || !mediaStream.active || !videoElement) { return; }
    if (!socket || socket.readyState !== WebSocket.OPEN) { return; }
    if (!cercoCtrl.estaCerradoOEditando()) { return; }
    if (!captureCanvas || !captureCtx) { return; }

    var vw = videoElement.videoWidth || 640;
    var vh = videoElement.videoHeight || 480;
    if (vw <= 0 || vh <= 0) { return; }

    captureCanvas.width = vw;
    captureCanvas.height = vh;
    try {
      captureCtx.drawImage(videoElement, 0, 0, vw, vh);
      var frameB64 = captureCanvas.toDataURL("image/jpeg", 0.72);
      esperandoDeteccion = true;
      socket.send(JSON.stringify({
        tipo: "procesar_frame",
        frame_b64: frameB64,
        ancho: vw,
        alto: vh
      }));
    } catch (err) {
      esperandoDeteccion = false;
    }
  }

  function iniciarBucleDeteccionCPU() {
    detenerBucleDeteccionCPU();
    timerDeteccionCPU = setInterval(capturarYEnviarFrameCerco, 220);
  }

  function detenerBucleDeteccionCPU() {
    if (timerDeteccionCPU !== null) {
      clearInterval(timerDeteccionCPU);
      timerDeteccionCPU = null;
    }
    esperandoDeteccion = false;
  }

  // ---------------------------------------------------------------------------
  // Gestión del Canal WebSocket (/ws/monitoreo)
  // ---------------------------------------------------------------------------
  function conectarWebSocket(alAbrirCallback) {
    if (socket && socket.readyState === WebSocket.OPEN) {
      if (alAbrirCallback) { alAbrirCallback(); }
      return;
    }

    if (socket && socket.readyState === WebSocket.CONNECTING) {
      if (alAbrirCallback) {
        socket.addEventListener("open", alAbrirCallback, { once: true });
      }
      return;
    }

    var protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    var wsUrl = protocol + "//" + window.location.host + "/ws/monitoreo?token=" + encodeURIComponent(token);
    socket = new WebSocket(wsUrl);

    socket.onopen = function () {
      cercoCtrl.sincronizarConServidorSiCerrado();
      if (alAbrirCallback) { alAbrirCallback(); }
    };

    socket.onmessage = function (event) {
      try {
        procesarMensajeServidor(JSON.parse(event.data));
      } catch (err) {
        // Trama no JSON ignorada defensivamente
      }
    };

    socket.onclose = function () {
      socket = null;
      if (rtspConectando || rtspActivo) {
        manejarFalloStreamRed("Se cerró el canal de transmisión con el servidor.");
      }
    };

    socket.onerror = function () {
      // Delegado al evento onclose
    };
  }

  function procesarMensajeServidor(data) {
    if (!data || !data.tipo) { return; }

    if (data.tipo === "rtsp_conectado") {
      rtspConectando = false;
      rtspActivo = true;
      VI.showFieldError("rtsp-url-input", "");

      if (videoElement) { videoElement.classList.add("hidden"); }
      if (rtspImgElement) { rtspImgElement.classList.remove("hidden"); }
      if (placeholderStage) { placeholderStage.classList.add("hidden"); }

      badgeEstadoCamara.textContent = "Cámara RTSP conectada";
      badgeEstadoCamara.className = "badge-pill badge-pill-live";
      btnIniciarCamara.textContent = "Detener Cámara";
      btnIniciarCamara.className = "btn btn-stop";
      btnIniciarCamara.disabled = false;

      cercoCtrl.habilitarAlConectar();
      return;
    }

    if (data.tipo === "fotograma_rtsp" && rtspActivo) {
      if (rtspImgElement && data.frame_b64) {
        rtspImgElement.src = "data:image/jpeg;base64," + data.frame_b64;
      }
      if (data.metricas) {
        actualizarMetricasDOM(data.metricas);
      }
      return;
    }

    if (data.tipo === "resultado_deteccion") {
      esperandoDeteccion = false;
      deteccionesActivas = Array.isArray(data.detecciones) ? data.detecciones : [];
      cercoCtrl.actualizarDetecciones(deteccionesActivas);
      actualizarMetricasDOM({
        inferencia_ms: data.inferencia_ms,
        area_cerco_pct: data.area_cerco_pct,
        peatones: data.peatones_detectados !== undefined ? data.peatones_detectados : deteccionesActivas.length,
        alertas: 0
      });
      return;
    }

    if (data.tipo === "error_procesamiento") {
      esperandoDeteccion = false;
      return;
    }

    if (data.tipo === "error_camara") {
      manejarFalloStreamRed(data.mensaje || "No se pudo abrir el enlace de la cámara.");
      return;
    }

    if (data.tipo === "telemetria" && data.metricas) {
      actualizarMetricasDOM(data.metricas);
    } else if (data.tipo === "cerco_confirmado") {
      actualizarMetricaArea(data.area_cerco_pct);
      cercoCtrl.actualizarEstadoServidor(data.estado);
    } else if (data.tipo === "cerco_limpiado") {
      deteccionesActivas = [];
      esperandoDeteccion = false;
      cercoCtrl.actualizarDetecciones([]);
      actualizarMetricaArea(0.0);
      actualizarMetricasDOM({ peatones: 0, alertas: 0 });
    } else if (data.tipo === "error_cerco" && cercoStatusHint) {
      cercoStatusHint.textContent = data.mensaje || "Error al validar cerco.";
    }
  }

  function manejarFalloStreamRed(mensajeError) {
    rtspConectando = false;
    rtspActivo = false;

    if (rtspImgElement) {
      rtspImgElement.removeAttribute("src");
      rtspImgElement.classList.add("hidden");
    }
    if (placeholderStage) { placeholderStage.classList.remove("hidden"); }

    badgeEstadoCamara.textContent = "Error en enlace";
    badgeEstadoCamara.className = "badge-pill badge-pill-error";
    btnIniciarCamara.textContent = "Iniciar Cámara";
    btnIniciarCamara.className = "btn btn-primary";
    btnIniciarCamara.disabled = false;

    VI.showFieldError("rtsp-url-input", mensajeError);
    cercoCtrl.limpiar(false);
  }

  function desconectarWebSocket() {
    if (!socket) { return; }
    try {
      if (socket.readyState === WebSocket.OPEN) {
        if (rtspActivo || rtspConectando) {
          socket.send(JSON.stringify({ tipo: "detener_rtsp" }));
        } else {
          socket.send(JSON.stringify({ tipo: "camara_estado", estado: "desconectada" }));
        }
      }
      socket.close(1000, "Vigilancia detenida por el operador");
    } catch (e) {
      // Cierre defensivo
    }
    socket = null;
  }

  // ---------------------------------------------------------------------------
  // Conexión por Cámara Local (PC) y por Enlace RTSP / IP (RF-03 / CP-02)
  // ---------------------------------------------------------------------------
  function iniciarCamaraLocal() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      badgeEstadoCamara.textContent = "Navegador sin soporte de cámara";
      badgeEstadoCamara.className = "badge-pill badge-pill-error";
      return;
    }

    badgeEstadoCamara.textContent = "Conectando cámara...";
    badgeEstadoCamara.className = "badge-pill";
    btnIniciarCamara.disabled = true;

    function onStreamSuccess(stream) {
      mediaStream = stream;
      if (rtspImgElement) { rtspImgElement.classList.add("hidden"); }
      videoElement.srcObject = stream;
      videoElement.classList.remove("hidden");
      placeholderStage.classList.add("hidden");

      var playPromise = videoElement.play();
      if (playPromise !== undefined) {
        playPromise.catch(function () { /* Autoplay gestionado */ });
      }

      badgeEstadoCamara.textContent = "Cámara conectada";
      badgeEstadoCamara.className = "badge-pill badge-pill-live";
      btnIniciarCamara.textContent = "Detener Cámara";
      btnIniciarCamara.className = "btn btn-stop";
      btnIniciarCamara.disabled = false;

      cercoCtrl.habilitarAlConectar();
      conectarWebSocket(function () {
        enviarMensajeWS({ tipo: "camara_estado", estado: "conectada" });
      });
      iniciarBucleDeteccionCPU();
    }

    function onStreamError(error) {
      btnIniciarCamara.disabled = false;
      btnIniciarCamara.textContent = "Iniciar Cámara";
      btnIniciarCamara.className = "btn btn-primary";

      if (error && error.name === "OverconstrainedError") {
        navigator.mediaDevices.getUserMedia({ video: true, audio: false })
          .then(onStreamSuccess)
          .catch(function () {
            badgeEstadoCamara.textContent = "Resolución no soportada";
            badgeEstadoCamara.className = "badge-pill badge-pill-error";
          });
        return;
      }

      var mapaErrores = {
        NotAllowedError: "Permiso denegado en navegador",
        PermissionDeniedError: "Permiso denegado en navegador",
        NotFoundError: "Cámara local no encontrada",
        DevicesNotFoundError: "Cámara local no encontrada",
        NotReadableError: "Cámara en uso por otra app",
        TrackStartError: "Cámara en uso por otra app"
      };
      badgeEstadoCamara.textContent = (error && mapaErrores[error.name]) || "Error al conectar cámara";
      badgeEstadoCamara.className = "badge-pill badge-pill-error";
    }

    navigator.mediaDevices.getUserMedia({
      video: { width: { ideal: 640 }, height: { ideal: 480 } },
      audio: false
    }).then(onStreamSuccess).catch(onStreamError);
  }

  function validarEnlaceRtspCliente(valor) {
    var limpio = (valor || "").trim();
    if (!limpio) {
      return "Ingrese el enlace RTSP o HTTP de la cámara antes de iniciar.";
    }
    if (!ESQUEMA_CAMARA_RE.test(limpio)) {
      return "Use un enlace válido que inicie con rtsp://, rtsps://, http:// o https://.";
    }
    return "";
  }

  function iniciarCamaraRtsp() {
    var url = inputRtspUrl ? inputRtspUrl.value.trim() : "";
    var errorValidacion = validarEnlaceRtspCliente(url);
    if (errorValidacion) {
      VI.showFieldError("rtsp-url-input", errorValidacion);
      if (inputRtspUrl) { inputRtspUrl.focus(); }
      return;
    }

    VI.showFieldError("rtsp-url-input", "");
    rtspConectando = true;
    badgeEstadoCamara.textContent = "Conectando enlace...";
    badgeEstadoCamara.className = "badge-pill";
    btnIniciarCamara.disabled = true;

    conectarWebSocket(function () {
      enviarMensajeWS({ tipo: "iniciar_rtsp", url: url });
    });
  }

  function detenerCamaraActiva() {
    detenerBucleDeteccionCPU();
    if (mediaStream) {
      mediaStream.getTracks().forEach(function (track) { track.stop(); });
      mediaStream = null;
    }

    var habiaRtsp = rtspActivo || rtspConectando;
    rtspActivo = false;
    rtspConectando = false;

    if (videoElement) {
      videoElement.srcObject = null;
      videoElement.classList.add("hidden");
    }
    if (rtspImgElement) {
      rtspImgElement.removeAttribute("src");
      rtspImgElement.classList.add("hidden");
    }
    if (placeholderStage) {
      placeholderStage.classList.remove("hidden");
    }

    badgeEstadoCamara.textContent = "Cámara desconectada";
    badgeEstadoCamara.className = "badge-pill";
    btnIniciarCamara.textContent = "Iniciar Cámara";
    btnIniciarCamara.className = "btn btn-primary";
    btnIniciarCamara.disabled = false;

    cercoCtrl.limpiar(false);
    reiniciarMetricasDOM();

    if (habiaRtsp && socket && socket.readyState === WebSocket.OPEN) {
      enviarMensajeWS({ tipo: "detener_rtsp" });
    }
    desconectarWebSocket();
  }

  function cambiarOrigenCamara(nuevoOrigen) {
    if (origenSeleccionado === nuevoOrigen) { return; }
    if (estaCamaraActiva() || rtspConectando) {
      detenerCamaraActiva();
    }

    origenSeleccionado = nuevoOrigen;
    VI.showFieldError("rtsp-url-input", "");

    var esRtsp = (nuevoOrigen === "rtsp");
    if (btnModoLocal) {
      btnModoLocal.classList.toggle("source-option-active", !esRtsp);
      btnModoLocal.setAttribute("aria-pressed", esRtsp ? "false" : "true");
    }
    if (btnModoRtsp) {
      btnModoRtsp.classList.toggle("source-option-active", esRtsp);
      btnModoRtsp.setAttribute("aria-pressed", esRtsp ? "true" : "false");
    }
    if (filaConfigRtsp) {
      filaConfigRtsp.classList.toggle("hidden", !esRtsp);
    }
    if (placeholderText) {
      placeholderText.textContent = esRtsp
        ? "Ingrese el enlace RTSP/IP arriba y presione Iniciar Cámara."
        : "Presione Iniciar Cámara para conectar la transmisión en vivo.";
    }
    if (esRtsp && inputRtspUrl) {
      inputRtspUrl.focus();
    }
  }

  // ---------------------------------------------------------------------------
  // Eventos de UI y Cierre de Sesión
  // ---------------------------------------------------------------------------
  if (btnModoLocal) {
    btnModoLocal.addEventListener("click", function () { cambiarOrigenCamara("local"); });
  }
  if (btnModoRtsp) {
    btnModoRtsp.addEventListener("click", function () { cambiarOrigenCamara("rtsp"); });
  }
  if (inputRtspUrl) {
    inputRtspUrl.addEventListener("input", function () { VI.showFieldError("rtsp-url-input", ""); });
    inputRtspUrl.addEventListener("keydown", function (ev) {
      if (ev.key === "Enter") {
        ev.preventDefault();
        if (!estaCamaraActiva() && !rtspConectando) { iniciarCamaraRtsp(); }
      }
    });
  }

  btnIniciarCamara.addEventListener("click", function () {
    if (estaCamaraActiva() || rtspConectando) {
      detenerCamaraActiva();
      return;
    }
    if (origenSeleccionado === "rtsp") {
      iniciarCamaraRtsp();
    } else {
      iniciarCamaraLocal();
    }
  });

  window.addEventListener("pagehide", function () {
    detenerCamaraActiva();
    var current = VI.getToken();
    if (current) {
      releaseSession(current);
      VI.clearToken();
    }
  });

  VI.byId("logout-button").addEventListener("click", function () {
    detenerCamaraActiva();
    var current = VI.getToken();
    VI.clearToken();
    if (!current) { window.location.replace("/login"); return; }
    releaseSession(current)
      .catch(function () { /* Expiración en servidor */ })
      .then(function () { window.location.replace("/login"); });
  });

  var etiquetasTrayectoria = { "1": "Baja", "2": "Media", "3": "Alta" };
  VI.byId("umbral-tiempo").addEventListener("input", function (event) {
    VI.byId("umbral-tiempo-valor").textContent = event.target.value + " s";
  });
  VI.byId("umbral-trayectoria").addEventListener("input", function (event) {
    VI.byId("umbral-trayectoria-valor").textContent = etiquetasTrayectoria[event.target.value] || "Media";
  });
})();
