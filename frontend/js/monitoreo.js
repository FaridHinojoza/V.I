/* Pantalla 3 — Monitoreo en Vivo (US-02 / RF-03 / CP-02).
 * Gestiona el ciclo de vida de la cámara en tiempo real mediante getUserMedia,
 * la señalización por canal WebSocket /ws/monitoreo y la guardia de sesión única.
 */
(function () {
  "use strict";

  var token = VI.getToken();
  var mediaStream = null;
  var socket = null;

  // Referencias a elementos del DOM
  var btnIniciarCamara = VI.byId("iniciar-camara");
  var btnDibujarCerco = VI.byId("dibujar-cerco");
  var badgeEstadoCamara = VI.byId("camara-estado");
  var videoElement = VI.byId("video-stream");
  var placeholderStage = VI.byId("stage-placeholder");

  function goToLogin() {
    VI.clearToken();
    window.location.replace("/login");
  }

  function releaseSession(currentToken) {
    // keepalive asegura que la petición de cierre sobreviva al cierre intempestivo de la pestaña.
    return fetch("/api/auth/logout", {
      method: "POST",
      headers: { "Authorization": "Bearer " + currentToken },
      keepalive: true
    });
  }

  // Guardia de acceso: sin token JWT válido en almacenamiento local, redirigir a inicio.
  if (!token) {
    goToLogin();
    return;
  }

  fetch("/api/auth/verificar", { headers: { "Authorization": "Bearer " + token } })
    .then(function (res) { if (!res.ok) { goToLogin(); } })
    .catch(function () { /* En caso de intermitencia de red, se mantiene la vista */ });

  // ---------------------------------------------------------------------------
  // Conexión y Gestión de Canal WebSocket (/ws/monitoreo)
  // ---------------------------------------------------------------------------
  function conectarWebSocket() {
    if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
      return;
    }

    var protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    var wsUrl = protocol + "//" + window.location.host + "/ws/monitoreo?token=" + encodeURIComponent(token);

    socket = new WebSocket(wsUrl);

    socket.onopen = function () {
      // Señalizar al servidor que la cámara inició transmisión en vivo
      socket.send(JSON.stringify({ tipo: "camara_estado", estado: "conectada" }));
    };

    socket.onmessage = function (event) {
      try {
        var data = JSON.parse(event.data);
        if (data.tipo === "telemetria" && data.metricas) {
          actualizarMetricasDOM(data.metricas);
        }
      } catch (err) {
        // Ignorar tramas no parseables
      }
    };

    socket.onclose = function () {
      socket = null;
    };

    socket.onerror = function () {
      // El navegador maneja el evento close subsiguiente
    };
  }

  function desconectarWebSocket() {
    if (socket) {
      try {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ tipo: "camara_estado", estado: "desconectada" }));
        }
        socket.close(1000, "Vigilancia detenida por el usuario");
      } catch (e) {
        // Cierre defensivo
      }
      socket = null;
    }
  }

  function actualizarMetricasDOM(metricas) {
    // Actualización de los 6 cuadros de métricas (RF-11)
    if (!metricas) { return; }
    var metricNodes = document.querySelectorAll(".metric-value");
    if (metricNodes.length >= 6) {
      if (metricas.fps !== undefined) { metricNodes[0].textContent = metricas.fps.toFixed(1) + " FPS"; }
      if (metricas.inferencia_ms !== undefined) { metricNodes[1].textContent = metricas.inferencia_ms.toFixed(1) + " ms"; }
      if (metricas.area_cerco_pct !== undefined) { metricNodes[2].textContent = metricas.area_cerco_pct.toFixed(1) + " %"; }
      if (metricas.cpu_pct !== undefined) { metricNodes[3].textContent = metricas.cpu_pct.toFixed(1) + " %"; }
      if (metricas.ram_mb !== undefined) { metricNodes[4].textContent = metricas.ram_mb.toFixed(0) + " MB"; }
      if (metricas.peatones !== undefined && metricas.alertas !== undefined) {
        metricNodes[5].textContent = metricas.peatones + " / " + metricas.alertas;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Ciclo de Vida de la Cámara en Tiempo Real (RF-03 / CP-02)
  // ---------------------------------------------------------------------------
  function iniciarCamara() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      console.warn("[VI] navigator.mediaDevices.getUserMedia no disponible.");
      badgeEstadoCamara.textContent = "Navegador sin soporte de cámara";
      badgeEstadoCamara.className = "badge-pill badge-pill-error";
      return;
    }

    // Indicador inmediato de intento de conexión
    badgeEstadoCamara.textContent = "Conectando cámara...";
    badgeEstadoCamara.className = "badge-pill";
    if (btnIniciarCamara) {
      btnIniciarCamara.disabled = true;
    }

    // Restricción innegociable RNF-01 / Tabla 2: video exclusivo, audio prohibido (false)
    var constraints = {
      video: { width: { ideal: 640 }, height: { ideal: 480 } },
      audio: false
    };

    function onStreamSuccess(stream) {
      mediaStream = stream;
      videoElement.srcObject = stream;
      videoElement.style.display = "block";
      placeholderStage.style.display = "none";

      var playPromise = videoElement.play();
      if (playPromise !== undefined) {
        playPromise.catch(function (e) {
          console.warn("[VI] Play error:", e);
        });
      }

      // Transición de estados de control visual
      badgeEstadoCamara.textContent = "Cámara conectada";
      badgeEstadoCamara.className = "badge-pill badge-pill-live";

      btnIniciarCamara.textContent = "Detener Cámara";
      btnIniciarCamara.className = "btn btn-stop";
      btnIniciarCamara.disabled = false;

      // Habilitar controles subsecuentes del flujo de vigilancia (US-03)
      if (btnDibujarCerco) {
        btnDibujarCerco.disabled = false;
      }

      // Abrir canal de telemetría y comunicación con el servidor
      conectarWebSocket();
    }

    function onStreamError(error) {
      if (btnIniciarCamara) {
        btnIniciarCamara.disabled = false;
        btnIniciarCamara.textContent = "Iniciar Cámara";
        btnIniciarCamara.className = "btn btn-primary";
      }
      console.error("[VI] Error getUserMedia:", error);

      var mensaje = "Error al conectar cámara";
      if (error.name === "NotAllowedError" || error.name === "PermissionDeniedError") {
        mensaje = "Permiso denegado en navegador";
      } else if (error.name === "NotFoundError" || error.name === "DevicesNotFoundError") {
        mensaje = "Cámara no encontrada";
      } else if (error.name === "NotReadableError" || error.name === "TrackStartError") {
        mensaje = "Cámara en uso por otra aplicación";
      } else if (error.name === "OverconstrainedError") {
        // Reintentar con restricciones genéricas mínimas si falló por resolución
        return navigator.mediaDevices.getUserMedia({ video: true, audio: false })
          .then(onStreamSuccess)
          .catch(function (fallbackErr) {
            badgeEstadoCamara.textContent = "Resolución no soportada";
            badgeEstadoCamara.className = "badge-pill badge-pill-error";
          });
      }

      badgeEstadoCamara.textContent = mensaje;
      badgeEstadoCamara.className = "badge-pill badge-pill-error";
    }

    navigator.mediaDevices.getUserMedia(constraints)
      .then(onStreamSuccess)
      .catch(onStreamError);
  }

  function detenerCamara() {
    // 1. Apagar físicamente todos los tracks del sensor de video
    if (mediaStream) {
      mediaStream.getTracks().forEach(function (track) {
        track.stop();
      });
      mediaStream = null;
    }

    // 2. Limpiar el elemento de video y restaurar el placeholder de espera
    if (videoElement) {
      videoElement.srcObject = null;
      videoElement.style.display = "none";
    }
    if (placeholderStage) {
      placeholderStage.style.display = "flex";
    }

    // 3. Restaurar estado de los botones e indicadores visuales
    badgeEstadoCamara.textContent = "Cámara desconectada";
    badgeEstadoCamara.className = "badge-pill";

    btnIniciarCamara.textContent = "Iniciar Cámara";
    btnIniciarCamara.className = "btn btn-primary";

    if (btnDibujarCerco) {
      btnDibujarCerco.disabled = true;
    }

    // 4. Cerrar canal WebSocket de monitoreo
    desconectarWebSocket();
  }

  // Conmutador del botón Iniciar / Detener Cámara
  btnIniciarCamara.addEventListener("click", function () {
    if (mediaStream && mediaStream.active) {
      detenerCamara();
    } else {
      iniciarCamara();
    }
  });

  // ---------------------------------------------------------------------------
  // Gestión de Cierre de Sesión y Salida de Navegador
  // ---------------------------------------------------------------------------
  VI.byId("logout-button").addEventListener("click", function () {
    detenerCamara();
    var current = VI.getToken();
    VI.clearToken();
    if (!current) { window.location.replace("/login"); return; }
    releaseSession(current)
      .catch(function () { /* La sesión expira automáticamente en servidor */ })
      .then(function () { window.location.replace("/login"); });
  });

  // Apagar cámara y liberar sesión al cerrar la pestaña o recargar
  window.addEventListener("pagehide", function () {
    detenerCamara();
    var current = VI.getToken();
    if (current) {
      releaseSession(current);
      VI.clearToken();
    }
  });

  // Controles de umbrales en UI
  var etiquetasTrayectoria = { "1": "Baja", "2": "Media", "3": "Alta" };
  VI.byId("umbral-tiempo").addEventListener("input", function (event) {
    VI.byId("umbral-tiempo-valor").textContent = event.target.value + " s";
  });
  VI.byId("umbral-trayectoria").addEventListener("input", function (event) {
    VI.byId("umbral-trayectoria-valor").textContent = etiquetasTrayectoria[event.target.value] || "Media";
  });

  // Intento de conexión inicial automática al cargar la vista de monitoreo (RF-03)
  setTimeout(function () {
    iniciarCamara();
  }, 150);
})();
