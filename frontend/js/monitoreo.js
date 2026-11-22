/* Pantalla 3 — Monitoreo en Vivo (US-02 / US-03 / RF-03 / RF-04 / RF-05 / RF-06 / CP-02 / CP-03).
 * Gestiona la cámara en tiempo real, el canal WebSocket /ws/monitoreo y el
 * controlador interactivo del cerco virtual dinámico de 4 a 6 vértices en HTML5 Canvas.
 */
(function () {
  "use strict";

  var token = VI.getToken();
  var mediaStream = null;
  var socket = null;

  // Elementos del DOM — Controles y Vistas
  var btnIniciarCamara = VI.byId("iniciar-camara");
  var btnDibujarCerco = VI.byId("dibujar-cerco");
  var btnCerrarCerco = VI.byId("cerrar-cerco");
  var btnEditarCerco = VI.byId("editar-cerco");
  var btnLimpiarCerco = VI.byId("limpiar-cerco");
  var badgeEstadoCamara = VI.byId("camara-estado");
  var cercoVerticesBadge = VI.byId("cerco-vertices-badge");
  var cercoStatusHint = VI.byId("cerco-status-hint");
  var videoElement = VI.byId("video-stream");
  var canvasElement = VI.byId("canvas-stage");
  var placeholderStage = VI.byId("stage-placeholder");

  // Contexto 2D del Canvas
  var ctx = canvasElement ? canvasElement.getContext("2d") : null;

  // Estado del Cerco Virtual en Frontend (en memoria de sesión / cero persistencia en BD)
  var modoCerco = "INACTIVO"; // "INACTIVO" | "DIBUJANDO" | "CERRADO" | "EDITANDO"
  var vertices = []; // Array de puntos normalizados {x: 0..1, y: 0..1}
  var arrastrandoIdx = null; // Índice del vértice siendo arrastrado con el ratón
  var estadoVisualCerco = "verde"; // "verde" (normal) | "amarillo" (observación) | "rojo" (alerta)

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

  // Guardia de acceso: sin token JWT válido en almacenamiento de sesión, redirigir
  if (!token) {
    goToLogin();
    return;
  }

  fetch("/api/auth/verificar", { headers: { "Authorization": "Bearer " + token } })
    .then(function (res) { if (!res.ok) { goToLogin(); } })
    .catch(function () { /* Intermitencia de red tolerada */ });

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
      socket.send(JSON.stringify({ tipo: "camara_estado", estado: "conectada" }));
      // Si ya había un cerco trazado antes de reconectar, sincronizarlo en memoria
      if (vertices.length >= 4 && modoCerco === "CERRADO") {
        socket.send(JSON.stringify({ tipo: "cerco_actualizado", vertices: vertices }));
      }
    };

    socket.onmessage = function (event) {
      try {
        var data = JSON.parse(event.data);
        if (data.tipo === "telemetria" && data.metricas) {
          actualizarMetricasDOM(data.metricas);
        } else if (data.tipo === "cerco_confirmado") {
          actualizarMetricaArea(data.area_cerco_pct);
          if (data.estado) {
            estadoVisualCerco = data.estado;
            renderizarLienzo();
          }
        } else if (data.tipo === "cerco_limpiado") {
          actualizarMetricaArea(0.0);
        } else if (data.tipo === "error_cerco") {
          if (cercoStatusHint) {
            cercoStatusHint.textContent = data.mensaje || "Error al validar cerco.";
          }
        }
      } catch (err) {
        // Trama ignorada defensivamente
      }
    };

    socket.onclose = function () {
      socket = null;
    };

    socket.onerror = function () {
      // Manejado automáticamente por evento close
    };
  }

  function desconectarWebSocket() {
    if (socket) {
      try {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ tipo: "camara_estado", estado: "desconectada" }));
        }
        socket.close(1000, "Vigilancia detenida por el operador");
      } catch (e) {
        // Cierre defensivo
      }
      socket = null;
    }
  }

  function actualizarMetricasDOM(metricas) {
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

  function actualizarMetricaArea(porcentaje) {
    var metricNodes = document.querySelectorAll(".metric-value");
    if (metricNodes.length >= 3 && porcentaje !== undefined) {
      metricNodes[2].textContent = Number(porcentaje).toFixed(1) + " %";
    }
  }

  // ---------------------------------------------------------------------------
  // Ciclo de Vida de la Cámara en Tiempo Real (RF-03 / CP-02)
  // ---------------------------------------------------------------------------
  function iniciarCamara() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      badgeEstadoCamara.textContent = "Navegador sin soporte de cámara";
      badgeEstadoCamara.className = "badge-pill badge-pill-error";
      return;
    }

    badgeEstadoCamara.textContent = "Conectando cámara...";
    badgeEstadoCamara.className = "badge-pill";
    if (btnIniciarCamara) { btnIniciarCamara.disabled = true; }

    var constraints = {
      video: { width: { ideal: 640 }, height: { ideal: 480 } },
      audio: false
    };

    function onStreamSuccess(stream) {
      mediaStream = stream;
      videoElement.srcObject = stream;
      videoElement.style.display = "block";
      canvasElement.style.display = "block";
      placeholderStage.style.display = "none";

      var playPromise = videoElement.play();
      if (playPromise !== undefined) {
        playPromise.catch(function (e) { console.warn("[VI] Play error:", e); });
      }

      badgeEstadoCamara.textContent = "Cámara conectada";
      badgeEstadoCamara.className = "badge-pill badge-pill-live";

      btnIniciarCamara.textContent = "Detener Cámara";
      btnIniciarCamara.className = "btn btn-stop";
      btnIniciarCamara.disabled = false;

      // Habilitar herramienta de trazado de cerco virtual (RF-05 / CP-03)
      if (btnDibujarCerco) { btnDibujarCerco.disabled = false; }

      sincronizarDimensionesCanvas();
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
        mensaje = "Cámara en uso por otra app";
      } else if (error.name === "OverconstrainedError") {
        return navigator.mediaDevices.getUserMedia({ video: true, audio: false })
          .then(onStreamSuccess)
          .catch(function () {
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
    if (mediaStream) {
      mediaStream.getTracks().forEach(function (track) { track.stop(); });
      mediaStream = null;
    }

    if (videoElement) {
      videoElement.srcObject = null;
      videoElement.style.display = "none";
    }
    if (canvasElement) {
      canvasElement.style.display = "none";
    }
    if (placeholderStage) {
      placeholderStage.style.display = "flex";
    }

    badgeEstadoCamara.textContent = "Cámara desconectada";
    badgeEstadoCamara.className = "badge-pill";

    btnIniciarCamara.textContent = "Iniciar Cámara";
    btnIniciarCamara.className = "btn btn-primary";

    // Deshabilitar herramientas de cerco
    if (btnDibujarCerco) { btnDibujarCerco.disabled = true; btnDibujarCerco.classList.remove("btn-active-tool"); }
    if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
    if (btnEditarCerco) { btnEditarCerco.disabled = true; btnEditarCerco.classList.remove("btn-active-tool"); }
    if (btnLimpiarCerco) { btnLimpiarCerco.disabled = true; }

    limpiarLienzoCerco(false);
    desconectarWebSocket();
  }

  btnIniciarCamara.addEventListener("click", function () {
    if (mediaStream && mediaStream.active) {
      detenerCamara();
    } else {
      iniciarCamara();
    }
  });

  // ---------------------------------------------------------------------------
  // Controlador de Cerco Virtual Dinámico en HTML5 Canvas (RF-04 / RF-05 / RF-06 / CP-03)
  // ---------------------------------------------------------------------------

  function sincronizarDimensionesCanvas() {
    if (!canvasElement) { return; }
    var rect = canvasElement.getBoundingClientRect();
    if (rect.width > 0 && rect.height > 0) {
      canvasElement.width = Math.round(rect.width);
      canvasElement.height = Math.round(rect.height);
      renderizarLienzo();
    }
  }

  window.addEventListener("resize", sincronizarDimensionesCanvas);

  function calcularAreaShoelace(pts) {
    if (!pts || pts.length < 4) { return 0.0; }
    var n = pts.length;
    var suma = 0.0;
    for (var i = 0; i < n; i++) {
      var j = (i + 1) % n;
      suma += (pts[i].x * pts[j].y) - (pts[j].x * pts[i].y);
    }
    return Math.abs(suma) * 50.0; // (abs(suma) / 2.0) * 100%
  }

  function renderizarLienzo() {
    if (!ctx || !canvasElement) { return; }
    ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);

    if (vertices.length === 0) { return; }

    var w = canvasElement.width;
    var h = canvasElement.height;

    // Paleta semántica del cerco (Verde normal, Amarillo advertencia, Rojo alerta)
    var colorTrazo = "#1f8a65";
    var colorRelleno = "rgba(31, 138, 101, 0.16)";
    if (estadoVisualCerco === "amarillo") {
      colorTrazo = "#c08532";
      colorRelleno = "rgba(192, 133, 50, 0.22)";
    } else if (estadoVisualCerco === "rojo") {
      colorTrazo = "#cf2d56";
      colorRelleno = "rgba(207, 45, 86, 0.28)";
    }

    // 1. Trazar el polígono
    ctx.beginPath();
    var p0x = vertices[0].x * w;
    var p0y = vertices[0].y * h;
    ctx.moveTo(p0x, p0y);

    for (var i = 1; i < vertices.length; i++) {
      ctx.lineTo(vertices[i].x * w, vertices[i].y * h);
    }

    if (modoCerco === "CERRADO" || modoCerco === "EDITANDO") {
      ctx.closePath();
      ctx.fillStyle = colorRelleno;
      ctx.fill();
    }

    ctx.strokeStyle = colorTrazo;
    ctx.lineWidth = 2.5;
    ctx.lineJoin = "round";
    ctx.lineCap = "round";
    ctx.stroke();

    // 2. Dibujar handles circulares en cada vértice
    for (var j = 0; j < vertices.length; j++) {
      var vx = vertices[j].x * w;
      var vy = vertices[j].y * h;

      ctx.beginPath();
      var radio = (modoCerco === "EDITANDO") ? 7 : 5;
      ctx.arc(vx, vy, radio, 0, Math.PI * 2);
      ctx.fillStyle = "#ffffff";
      ctx.fill();
      ctx.strokeStyle = (j === 0 && modoCerco === "DIBUJANDO" && vertices.length >= 4) ? "#f54e00" : "#26251e";
      ctx.lineWidth = (j === 0 && modoCerco === "DIBUJANDO" && vertices.length >= 4) ? 3 : 2;
      ctx.stroke();

      // Indicador numérico del vértice (1..6)
      if (modoCerco === "DIBUJANDO" || modoCerco === "EDITANDO") {
        ctx.fillStyle = "#26251e";
        ctx.font = "bold 10px monospace";
        ctx.fillText(String(j + 1), vx + 8, vy - 6);
      }
    }
  }

  function obtenerPuntoCanvas(event) {
    var rect = canvasElement.getBoundingClientRect();
    var clientX = event.clientX;
    var clientY = event.clientY;
    var px = (clientX - rect.left) / rect.width;
    var py = (clientY - rect.top) / rect.height;
    return {
      x: Math.max(0.0, Math.min(1.0, px)),
      y: Math.max(0.0, Math.min(1.0, py))
    };
  }

  function encontrarVerticeCercano(puntoNorm, radioPixeles) {
    var w = canvasElement.width;
    var h = canvasElement.height;
    var px = puntoNorm.x * w;
    var py = puntoNorm.y * h;

    for (var i = 0; i < vertices.length; i++) {
      var vx = vertices[i].x * w;
      var vy = vertices[i].y * h;
      var dist = Math.hypot(px - vx, py - vy);
      if (dist <= radioPixeles) {
        return i;
      }
    }
    return -1;
  }

  // Activar Modo Trazado
  if (btnDibujarCerco) {
    btnDibujarCerco.addEventListener("click", function () {
      sincronizarDimensionesCanvas();
      modoCerco = "DIBUJANDO";
      vertices = [];
      estadoVisualCerco = "verde";

      btnDibujarCerco.classList.add("btn-active-tool");
      if (btnEditarCerco) { btnEditarCerco.classList.remove("btn-active-tool"); btnEditarCerco.disabled = true; }
      if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
      if (btnLimpiarCerco) { btnLimpiarCerco.disabled = false; }

      canvasElement.className = "stage-canvas cursor-draw";
      cercoVerticesBadge.style.display = "inline-block";
      cercoVerticesBadge.textContent = "0 / 6 vértices";
      cercoStatusHint.textContent = "Haga clic para colocar de 4 a 6 vértices.";

      renderizarLienzo();
    });
  }

  // Cerrar Cerco (RF-05 / CP-03)
  function cerrarPoligonoCerco() {
    if (vertices.length < 4) {
      cercoStatusHint.textContent = "Bloqueado: Mínimo 4 vértices requeridos (CP-03).";
      return;
    }

    modoCerco = "CERRADO";
    canvasElement.className = "stage-canvas";
    if (btnDibujarCerco) { btnDibujarCerco.classList.remove("btn-active-tool"); }
    if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
    if (btnEditarCerco) { btnEditarCerco.disabled = false; btnEditarCerco.classList.remove("btn-active-tool"); }
    if (btnLimpiarCerco) { btnLimpiarCerco.disabled = false; }

    var areaPct = calcularAreaShoelace(vertices);
    actualizarMetricaArea(areaPct);
    cercoStatusHint.textContent = "Cerco activo (" + vertices.length + " vértices). Vigilancia lista.";

    // Notificar al servidor FastAPI por canal WebSocket
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        tipo: "cerco_actualizado",
        vertices: vertices
      }));
    }

    renderizarLienzo();
  }

  if (btnCerrarCerco) {
    btnCerrarCerco.addEventListener("click", function () {
      cerrarPoligonoCerco();
    });
  }

  // Alternar Modo Edición (arrastre en caliente de esquinas RF-06)
  if (btnEditarCerco) {
    btnEditarCerco.addEventListener("click", function () {
      if (modoCerco === "CERRADO") {
        modoCerco = "EDITANDO";
        btnEditarCerco.classList.add("btn-active-tool");
        canvasElement.className = "stage-canvas cursor-edit";
        cercoStatusHint.textContent = "Arrastre cualquier vértice con el mouse para reajustar la zona.";
      } else if (modoCerco === "EDITANDO") {
        modoCerco = "CERRADO";
        btnEditarCerco.classList.remove("btn-active-tool");
        canvasElement.className = "stage-canvas";
        cercoStatusHint.textContent = "Cerco reajustado y sincronizado.";

        // Notificar al servidor el cerco reajustado
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({
            tipo: "cerco_actualizado",
            vertices: vertices
          }));
        }
      }
      renderizarLienzo();
    });
  }

  // Limpiar Cerco (RF-06 / CP-03)
  function limpiarLienzoCerco(notificarWS) {
    vertices = [];
    modoCerco = "INACTIVO";
    arrastrandoIdx = null;
    estadoVisualCerco = "verde";

    if (canvasElement) {
      canvasElement.className = "stage-canvas";
      if (ctx) { ctx.clearRect(0, 0, canvasElement.width, canvasElement.height); }
    }

    if (btnDibujarCerco) {
      btnDibujarCerco.classList.remove("btn-active-tool");
      btnDibujarCerco.disabled = !(mediaStream && mediaStream.active);
    }
    if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
    if (btnEditarCerco) { btnEditarCerco.disabled = true; btnEditarCerco.classList.remove("btn-active-tool"); }
    if (btnLimpiarCerco) { btnLimpiarCerco.disabled = true; }

    if (cercoVerticesBadge) { cercoVerticesBadge.style.display = "none"; }
    if (cercoStatusHint) { cercoStatusHint.textContent = "Cerco limpiado."; }

    actualizarMetricaArea(0.0);

    if (notificarWS && socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ tipo: "limpiar_cerco" }));
    }
  }

  if (btnLimpiarCerco) {
    btnLimpiarCerco.addEventListener("click", function () {
      limpiarLienzoCerco(true);
    });
  }

  // Manejo de Clics y Arrastre en Canvas
  if (canvasElement) {
    canvasElement.addEventListener("click", function (event) {
      if (modoCerco !== "DIBUJANDO") { return; }

      var pt = obtenerPuntoCanvas(event);

      // Si ya hay al menos 4 vértices y se hace clic cerca del vértice 0, cerrar
      if (vertices.length >= 4) {
        var idxCercano = encontrarVerticeCercano(pt, 22);
        if (idxCercano === 0) {
          cerrarPoligonoCerco();
          return;
        }
      }

      // Restricción innegociable RF-05 / CP-03: máximo 6 vértices
      if (vertices.length >= 6) {
        cercoStatusHint.textContent = "Límite alcanzado: Máximo 6 vértices permitidos (CP-03).";
        return;
      }

      vertices.push(pt);
      cercoVerticesBadge.textContent = vertices.length + " / 6 vértices";

      if (vertices.length >= 4) {
        if (btnCerrarCerco) { btnCerrarCerco.disabled = false; }
        cercoStatusHint.textContent = "Puede presionar 'Cerrar Cerco' o colocar hasta 6 puntos.";
      } else {
        cercoStatusHint.textContent = "Vértice " + vertices.length + " colocado (mínimo 4).";
      }

      // Auto-cierre al alcanzar el 6.° punto
      if (vertices.length === 6) {
        cerrarPoligonoCerco();
        return;
      }

      renderizarLienzo();
    });

    canvasElement.addEventListener("mousedown", function (event) {
      if (modoCerco !== "EDITANDO") { return; }
      var pt = obtenerPuntoCanvas(event);
      var idx = encontrarVerticeCercano(pt, 16);
      if (idx !== -1) {
        arrastrandoIdx = idx;
        canvasElement.className = "stage-canvas cursor-dragging";
      }
    });

    canvasElement.addEventListener("mousemove", function (event) {
      if (modoCerco === "EDITANDO" && arrastrandoIdx !== null) {
        var pt = obtenerPuntoCanvas(event);
        vertices[arrastrandoIdx] = pt;

        var areaPct = calcularAreaShoelace(vertices);
        actualizarMetricaArea(areaPct);
        renderizarLienzo();
      }
    });

    function finalizarArrastre() {
      if (modoCerco === "EDITANDO" && arrastrandoIdx !== null) {
        arrastrandoIdx = null;
        canvasElement.className = "stage-canvas cursor-edit";

        // Emitir reajuste en caliente hacia el backend
        if (socket && socket.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({
            tipo: "cerco_actualizado",
            vertices: vertices
          }));
        }
      }
    }

    canvasElement.addEventListener("mouseup", finalizarArrastre);
    canvasElement.addEventListener("mouseleave", finalizarArrastre);
  }

  // ---------------------------------------------------------------------------
  // Gestión de Cierre de Sesión y Salida de Navegador
  // ---------------------------------------------------------------------------
  VI.byId("logout-button").addEventListener("click", function () {
    detenerCamara();
    var current = VI.getToken();
    VI.clearToken();
    if (!current) { window.location.replace("/login"); return; }
    releaseSession(current)
      .catch(function () { /* Expiración en servidor */ })
      .then(function () { window.location.replace("/login"); });
  });

  // Controles de umbrales en UI
  var etiquetasTrayectoria = { "1": "Baja", "2": "Media", "3": "Alta" };
  VI.byId("umbral-tiempo").addEventListener("input", function (event) {
    VI.byId("umbral-tiempo-valor").textContent = event.target.value + " s";
  });
  VI.byId("umbral-trayectoria").addEventListener("input", function (event) {
    VI.byId("umbral-trayectoria-valor").textContent = etiquetasTrayectoria[event.target.value] || "Media";
  });

  // Intento de conexión inicial automática al entrar a la vista (RF-03)
  setTimeout(function () {
    iniciarCamara();
  }, 150);
})();
