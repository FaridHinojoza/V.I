/* Controlador modular del Cerco Virtual Dinámico y Cajas YOLO en HTML5 Canvas (US-03 / US-04).
 * Opera en memoria de la sesión actual (4 a 6 vértices) tanto sobre cámara local como sobre flujo RTSP.
 */
(function () {
  "use strict";

  function calcularAreaShoelace(pts) {
    if (!pts || pts.length < 4) { return 0.0; }
    var n = pts.length;
    var suma = 0.0;
    for (var i = 0; i < n; i++) {
      var j = (i + 1) % n;
      suma += (pts[i].x * pts[j].y) - (pts[j].x * pts[i].y);
    }
    return Math.abs(suma) * 50.0;
  }

  function dibujarCajasDeteccion(ctx, w, h, cajas) {
    for (var k = 0; k < cajas.length; k++) {
      var det = cajas[k];
      var bx = det.x1 * w;
      var by = det.y1 * h;
      var bw = Math.max(4, (det.x2 - det.x1) * w);
      var bh = Math.max(4, (det.y2 - det.y1) * h);

      ctx.strokeStyle = "#f54e00";
      ctx.lineWidth = 2;
      ctx.strokeRect(bx, by, bw, bh);

      var confPct = Math.round((Number(det.confianza) || 0) * 100);
      var etiqueta = "Persona " + confPct + "%";
      ctx.font = "600 11px monospace";
      var anchoTexto = ctx.measureText(etiqueta).width + 10;
      var altoEtiqueta = 18;
      var etiqY = by >= altoEtiqueta ? by - altoEtiqueta : by;

      ctx.fillStyle = "#26251e";
      ctx.fillRect(bx, etiqY, anchoTexto, altoEtiqueta);
      ctx.fillStyle = "#fafaf7";
      ctx.fillText(etiqueta, bx + 5, etiqY + 13);
    }
  }

  function crearControladorCerco(opciones) {
    var canvasElement = opciones.canvasElement;
    var btnDibujarCerco = opciones.btnDibujarCerco;
    var btnCerrarCerco = opciones.btnCerrarCerco;
    var btnEditarCerco = opciones.btnEditarCerco;
    var btnLimpiarCerco = opciones.btnLimpiarCerco;
    var cercoVerticesBadge = opciones.cercoVerticesBadge;
    var cercoStatusHint = opciones.cercoStatusHint;
    var estaCamaraActiva = opciones.estaCamaraActiva;
    var enviarMensajeWS = opciones.enviarMensajeWS;
    var alActualizarArea = opciones.alActualizarArea;
    var alLimpiarDetecciones = opciones.alLimpiarDetecciones;

    var ctx = canvasElement ? canvasElement.getContext("2d") : null;
    var modoCerco = "INACTIVO"; // "INACTIVO" | "DIBUJANDO" | "CERRADO" | "EDITANDO"
    var vertices = [];
    var cajasActivas = [];
    var arrastrandoIdx = null;
    var estadoVisualCerco = "verde";

    function obtenerColoresEstado() {
      if (estadoVisualCerco === "amarillo") {
        return { trazo: "#c08532", relleno: "rgba(192, 133, 50, 0.22)" };
      }
      if (estadoVisualCerco === "rojo") {
        return { trazo: "#cf2d56", relleno: "rgba(207, 45, 86, 0.28)" };
      }
      return { trazo: "#1f8a65", relleno: "rgba(31, 138, 101, 0.16)" };
    }

    function renderizarLienzo() {
      if (!ctx || !canvasElement) { return; }
      ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);
      if (vertices.length === 0) { return; }

      var w = canvasElement.width;
      var h = canvasElement.height;
      var paleta = obtenerColoresEstado();

      ctx.beginPath();
      ctx.moveTo(vertices[0].x * w, vertices[0].y * h);
      for (var i = 1; i < vertices.length; i++) {
        ctx.lineTo(vertices[i].x * w, vertices[i].y * h);
      }

      if (modoCerco === "CERRADO" || modoCerco === "EDITANDO") {
        ctx.closePath();
        ctx.fillStyle = paleta.relleno;
        ctx.fill();
      }

      ctx.strokeStyle = paleta.trazo;
      ctx.lineWidth = 2.5;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke();

      for (var j = 0; j < vertices.length; j++) {
        var vx = vertices[j].x * w;
        var vy = vertices[j].y * h;
        var esCierre = (j === 0 && modoCerco === "DIBUJANDO" && vertices.length >= 4);

        ctx.beginPath();
        ctx.arc(vx, vy, (modoCerco === "EDITANDO") ? 7 : 5, 0, Math.PI * 2);
        ctx.fillStyle = "#ffffff";
        ctx.fill();
        ctx.strokeStyle = esCierre ? "#f54e00" : "#26251e";
        ctx.lineWidth = esCierre ? 3 : 2;
        ctx.stroke();

        if (modoCerco === "DIBUJANDO" || modoCerco === "EDITANDO") {
          ctx.fillStyle = "#26251e";
          ctx.font = "bold 10px monospace";
          ctx.fillText(String(j + 1), vx + 8, vy - 6);
        }
      }

      if ((modoCerco === "CERRADO" || modoCerco === "EDITANDO") && cajasActivas.length > 0) {
        dibujarCajasDeteccion(ctx, w, h, cajasActivas);
      }
    }

    function sincronizarDimensiones() {
      if (!canvasElement) { return; }
      var rect = canvasElement.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        canvasElement.width = Math.round(rect.width);
        canvasElement.height = Math.round(rect.height);
        renderizarLienzo();
      }
    }

    function obtenerPuntoCanvas(event) {
      var rect = canvasElement.getBoundingClientRect();
      var px = (event.clientX - rect.left) / rect.width;
      var py = (event.clientY - rect.top) / rect.height;
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
        var dist = Math.hypot(px - (vertices[i].x * w), py - (vertices[i].y * h));
        if (dist <= radioPixeles) { return i; }
      }
      return -1;
    }

    function cerrarPoligonoCerco() {
      if (vertices.length < 4) {
        if (cercoStatusHint) {
          cercoStatusHint.textContent = "Bloqueado: Mínimo 4 vértices requeridos (CP-03).";
        }
        return;
      }

      modoCerco = "CERRADO";
      canvasElement.className = "stage-canvas";
      if (btnDibujarCerco) { btnDibujarCerco.classList.remove("btn-active-tool"); }
      if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
      if (btnEditarCerco) {
        btnEditarCerco.disabled = false;
        btnEditarCerco.classList.remove("btn-active-tool");
        btnEditarCerco.textContent = "Editar Cerco";
      }
      if (btnLimpiarCerco) { btnLimpiarCerco.disabled = false; }

      alActualizarArea(calcularAreaShoelace(vertices));
      if (cercoStatusHint) {
        cercoStatusHint.textContent = "Cerco activo (" + vertices.length + " vértices). Vigilancia lista.";
      }
      enviarMensajeWS({ tipo: "cerco_actualizado", vertices: vertices });
      renderizarLienzo();
    }

    function limpiar(notificarWS) {
      vertices = [];
      cajasActivas = [];
      modoCerco = "INACTIVO";
      arrastrandoIdx = null;
      estadoVisualCerco = "verde";

      if (alLimpiarDetecciones) { alLimpiarDetecciones(); }

      if (canvasElement) {
        var oculto = !estaCamaraActiva();
        canvasElement.className = oculto ? "stage-canvas hidden" : "stage-canvas";
        if (ctx) { ctx.clearRect(0, 0, canvasElement.width, canvasElement.height); }
      }

      if (btnDibujarCerco) {
        btnDibujarCerco.classList.remove("btn-active-tool");
        btnDibujarCerco.disabled = !estaCamaraActiva();
      }
      if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
      if (btnEditarCerco) {
        btnEditarCerco.disabled = true;
        btnEditarCerco.classList.remove("btn-active-tool");
        btnEditarCerco.textContent = "Editar Cerco";
      }
      if (btnLimpiarCerco) { btnLimpiarCerco.disabled = true; }

      if (cercoVerticesBadge) { cercoVerticesBadge.classList.add("hidden"); }
      if (cercoStatusHint) { cercoStatusHint.textContent = notificarWS ? "Cerco limpiado." : ""; }

      alActualizarArea(0.0);
      if (notificarWS) {
        enviarMensajeWS({ tipo: "limpiar_cerco" });
      }
    }

    if (btnDibujarCerco) {
      btnDibujarCerco.addEventListener("click", function () {
        sincronizarDimensiones();
        modoCerco = "DIBUJANDO";
        vertices = [];
        cajasActivas = [];
        estadoVisualCerco = "verde";
        if (alLimpiarDetecciones) { alLimpiarDetecciones(); }

        btnDibujarCerco.classList.add("btn-active-tool");
        if (btnEditarCerco) {
          btnEditarCerco.classList.remove("btn-active-tool");
          btnEditarCerco.textContent = "Editar Cerco";
          btnEditarCerco.disabled = true;
        }
        if (btnCerrarCerco) { btnCerrarCerco.disabled = true; }
        if (btnLimpiarCerco) { btnLimpiarCerco.disabled = false; }

        canvasElement.className = "stage-canvas cursor-draw";
        if (cercoVerticesBadge) {
          cercoVerticesBadge.classList.remove("hidden");
          cercoVerticesBadge.textContent = "0 / 6 vértices";
        }
        if (cercoStatusHint) {
          cercoStatusHint.textContent = "Haga clic para colocar de 4 a 6 vértices.";
        }
        renderizarLienzo();
      });
    }

    if (btnCerrarCerco) {
      btnCerrarCerco.addEventListener("click", cerrarPoligonoCerco);
    }

    if (btnEditarCerco) {
      btnEditarCerco.addEventListener("click", function () {
        if (modoCerco === "CERRADO") {
          modoCerco = "EDITANDO";
          btnEditarCerco.classList.add("btn-active-tool");
          btnEditarCerco.textContent = "Dejar de editar";
          canvasElement.className = "stage-canvas cursor-edit";
          if (cercoStatusHint) {
            cercoStatusHint.textContent = "Arrastre cualquier vértice con el mouse para reajustar la zona.";
          }
        } else if (modoCerco === "EDITANDO") {
          modoCerco = "CERRADO";
          btnEditarCerco.classList.remove("btn-active-tool");
          btnEditarCerco.textContent = "Editar Cerco";
          canvasElement.className = "stage-canvas";
          if (cercoStatusHint) {
            cercoStatusHint.textContent = "Cerco reajustado y sincronizado.";
          }
          enviarMensajeWS({ tipo: "cerco_actualizado", vertices: vertices });
        }
        renderizarLienzo();
      });
    }

    if (btnLimpiarCerco) {
      btnLimpiarCerco.addEventListener("click", function () { limpiar(true); });
    }

    if (canvasElement) {
      canvasElement.addEventListener("click", function (event) {
        if (modoCerco !== "DIBUJANDO") { return; }
        var pt = obtenerPuntoCanvas(event);

        if (vertices.length >= 4 && encontrarVerticeCercano(pt, 22) === 0) {
          cerrarPoligonoCerco();
          return;
        }
        if (vertices.length >= 6) {
          if (cercoStatusHint) {
            cercoStatusHint.textContent = "Límite alcanzado: Máximo 6 vértices permitidos (CP-03).";
          }
          return;
        }

        vertices.push(pt);
        if (cercoVerticesBadge) { cercoVerticesBadge.textContent = vertices.length + " / 6 vértices"; }

        if (vertices.length >= 4) {
          if (btnCerrarCerco) { btnCerrarCerco.disabled = false; }
          if (cercoStatusHint) {
            cercoStatusHint.textContent = "Puede presionar 'Cerrar Cerco' o colocar hasta 6 puntos.";
          }
        } else if (cercoStatusHint) {
          cercoStatusHint.textContent = "Vértice " + vertices.length + " colocado (mínimo 4).";
        }

        if (vertices.length === 6) {
          cerrarPoligonoCerco();
          return;
        }
        renderizarLienzo();
      });

      canvasElement.addEventListener("mousedown", function (event) {
        if (modoCerco !== "EDITANDO") { return; }
        var idx = encontrarVerticeCercano(obtenerPuntoCanvas(event), 16);
        if (idx !== -1) {
          arrastrandoIdx = idx;
          canvasElement.className = "stage-canvas cursor-dragging";
        }
      });

      canvasElement.addEventListener("mousemove", function (event) {
        if (modoCerco === "EDITANDO" && arrastrandoIdx !== null) {
          vertices[arrastrandoIdx] = obtenerPuntoCanvas(event);
          alActualizarArea(calcularAreaShoelace(vertices));
          renderizarLienzo();
        }
      });

      function finalizarArrastre() {
        if (modoCerco === "EDITANDO" && arrastrandoIdx !== null) {
          arrastrandoIdx = null;
          canvasElement.className = "stage-canvas cursor-edit";
          enviarMensajeWS({ tipo: "cerco_actualizado", vertices: vertices });
        }
      }

      canvasElement.addEventListener("mouseup", finalizarArrastre);
      canvasElement.addEventListener("mouseleave", finalizarArrastre);
    }

    window.addEventListener("resize", sincronizarDimensiones);

    return {
      sincronizarDimensiones: sincronizarDimensiones,
      limpiar: limpiar,
      estaCerradoOEditando: function () {
        return (modoCerco === "CERRADO" || modoCerco === "EDITANDO") && vertices.length >= 4;
      },
      habilitarAlConectar: function () {
        if (canvasElement) { canvasElement.classList.remove("hidden"); }
        if (btnDibujarCerco) { btnDibujarCerco.disabled = false; }
        sincronizarDimensiones();
      },
      sincronizarConServidorSiCerrado: function () {
        if (vertices.length >= 4 && modoCerco === "CERRADO") {
          enviarMensajeWS({ tipo: "cerco_actualizado", vertices: vertices });
        }
      },
      actualizarEstadoServidor: function (nuevoEstado) {
        if (nuevoEstado) {
          estadoVisualCerco = nuevoEstado;
          renderizarLienzo();
        }
      },
      actualizarDetecciones: function (nuevasCajas) {
        cajasActivas = Array.isArray(nuevasCajas) ? nuevasCajas : [];
        renderizarLienzo();
      }
    };
  }

  window.VICerco = { crearControladorCerco: crearControladorCerco };
})();
