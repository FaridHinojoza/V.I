"""Router y controlador WebSocket para Monitoreo en Vivo (US-02 / US-03 / US-04).

Gobierna el canal bidireccional /ws/monitoreo con autenticación obligatoria
por token JWT, soporte dual para cámara local (PC) o enlace de cámara en red (RTSP / IP),
ciclo de vida del cerco virtual en memoria, aislamiento espacial pre-inferencia (RNF-02)
y detección de peatones con YOLO sobre CPU y RAM (RF-03 a RF-07, RNF-01, RNF-04, CP-02 a CP-04).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
from typing import Any, Callable, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.concurrency import ejecutar_inferencia_cpu
from backend.app.core.config import Settings
from backend.app.domain.cerco_virtual import (
    CercoInvalidoError,
    CercoVirtualEnMemoria,
)
from backend.app.domain.ports import IDetectorPeatones
from backend.app.vision.capturador_rtsp import (
    CapturadorRTSP,
    URLCamaraInvalidaError,
)
from backend.app.vision.estrategias_roi import EstrategiaCercoVirtual
from backend.app.vision.yolo_detector import (
    DetectorYOLOCPU,
    FrameInvalidoError,
    decodificar_frame_base64,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Monitoreo en Vivo"])

_INTERVALO_FRAME_RTSP_SEG = 0.055
_INTERVALO_MIN_YOLO_RTSP_SEG = 0.20


def _ahora_iso() -> str:
    """Devuelve la marca de tiempo actual en formato ISO-8601 UTC."""
    return datetime.now(timezone.utc).isoformat()


async def _enviar_json_seguro(
    websocket: WebSocket, envio_lock: asyncio.Lock, payload: dict[str, Any]
) -> None:
    """Serializa el envío por WebSocket evitando colisiones entre corrutinas concurrentes."""
    async with envio_lock:
        await websocket.send_json(payload)


def _obtener_detector_ws(websocket: WebSocket) -> IDetectorPeatones:
    """Resuelve la instancia del detector YOLO en CPU desde app.state o el Singleton."""
    detector_inyectado: Optional[IDetectorPeatones] = getattr(
        websocket.app.state, "detector_yolo", None
    )
    if detector_inyectado is not None:
        return detector_inyectado

    settings: Optional[Settings] = getattr(websocket.app.state, "settings", None)
    model_path = settings.yolo_model_path if settings is not None else "models/yolo11n.pt"
    return DetectorYOLOCPU.obtener_instancia(model_path=model_path)


def _crear_estrategia_cerco_ws(websocket: WebSocket) -> EstrategiaCercoVirtual:
    """Construye la estrategia de aislamiento espacial ROI según la configuración activa."""
    settings: Optional[Settings] = getattr(websocket.app.state, "settings", None)
    if settings is not None:
        return EstrategiaCercoVirtual(
            padding_pct=settings.roi_padding_pct,
            imgsz_max=settings.yolo_imgsz_max,
            conf_min=settings.yolo_conf_threshold,
        )
    return EstrategiaCercoVirtual()


class _GestorStreamRTSPSesion:
    """Administra la captura RTSP y la inferencia YOLO en segundo plano sobre CPU/RAM."""

    def __init__(
        self,
        websocket: WebSocket,
        envio_lock: asyncio.Lock,
        cerco_activo: CercoVirtualEnMemoria,
        estrategia_cerco: EstrategiaCercoVirtual,
        detector: IDetectorPeatones,
        capturador_factory: Callable[[str], CapturadorRTSP],
    ) -> None:
        self._ws = websocket
        self._envio_lock = envio_lock
        self._cerco = cerco_activo
        self._estrategia = estrategia_cerco
        self._detector = detector
        self._factory = capturador_factory
        self._capturador: Optional[CapturadorRTSP] = None
        self._tarea_emision: Optional[asyncio.Task[None]] = None
        self._tarea_yolo: Optional[asyncio.Task[None]] = None
        self._ultimo_disparo_yolo: float = 0.0
        self._ultima_inferencia_ms: float = 0.0
        self._ultimos_peatones: int = 0

    def reiniciar_telemetria_cerco(self) -> None:
        """Limpia los contadores de inferencia cuando el usuario borra el cerco activo."""
        self._ultima_inferencia_ms = 0.0
        self._ultimos_peatones = 0

    async def iniciar(self, url_raw: str) -> None:
        """Valida, conecta e inicia la emisión continua del enlace RTSP solicitado."""
        await self.detener(notificar_cliente=False)
        try:
            capturador = self._factory(url_raw)
            ancho, alto = await asyncio.to_thread(capturador.conectar)
        except (URLCamaraInvalidaError, ConnectionError) as err:
            logger.warning("Fallo al iniciar cámara por enlace: %s", err)
            await _enviar_json_seguro(
                self._ws,
                self._envio_lock,
                {
                    "tipo": "error_camara",
                    "mensaje": str(err),
                    "timestamp": _ahora_iso(),
                },
            )
            return

        self._capturador = capturador
        self.reiniciar_telemetria_cerco()
        await _enviar_json_seguro(
            self._ws,
            self._envio_lock,
            {
                "tipo": "rtsp_conectado",
                "url": capturador.url_enmascarada,
                "ancho": ancho,
                "alto": alto,
                "timestamp": _ahora_iso(),
            },
        )
        self._tarea_emision = asyncio.create_task(self._bucle_emision(capturador))

    async def detener(self, notificar_cliente: bool = False) -> None:
        """Cancela las tareas activas de captura e inferencia y libera el descriptor OpenCV."""
        capturador = self._capturador
        tarea_emision = self._tarea_emision
        tarea_yolo = self._tarea_yolo
        self._capturador = None
        self._tarea_emision = None
        self._tarea_yolo = None
        self.reiniciar_telemetria_cerco()

        if capturador is not None:
            await asyncio.to_thread(capturador.detener)

        for tarea in (tarea_emision, tarea_yolo):
            if tarea is not None and not tarea.done():
                tarea.cancel()
                try:
                    await tarea
                except (asyncio.CancelledError, Exception):
                    pass

        if notificar_cliente:
            await _enviar_json_seguro(
                self._ws,
                self._envio_lock,
                {"tipo": "rtsp_detenido", "timestamp": _ahora_iso()},
            )

    def _programar_yolo_si_aplica(self, frame_bgr: Any) -> None:
        """Lanza detección YOLO con backpressure sin bloquear la fluidez del video RTSP."""
        if frame_bgr is None or not self._cerco.esta_cerrado:
            return
        if self._tarea_yolo is not None and not self._tarea_yolo.done():
            return
        ahora = time.perf_counter()
        if (ahora - self._ultimo_disparo_yolo) < _INTERVALO_MIN_YOLO_RTSP_SEG:
            return

        self._ultimo_disparo_yolo = ahora
        self._tarea_yolo = asyncio.create_task(self._ejecutar_yolo_rtsp(frame_bgr))

    async def _ejecutar_yolo_rtsp(self, frame_bgr: Any) -> None:
        """Ejecuta EstrategiaCercoVirtual sobre el cuadro BGR en memoria y emite detecciones."""
        try:
            resultado = await ejecutar_inferencia_cpu(
                self._estrategia.procesar,
                frame_bgr,
                self._cerco,
                self._detector,
            )
            if self._capturador is None or not self._capturador.activo:
                return

            self._ultima_inferencia_ms = float(resultado.inferencia_ms)
            self._ultimos_peatones = int(resultado.peatones_detectados)
            respuesta = resultado.to_dict()
            respuesta["tipo"] = "resultado_deteccion"
            respuesta["timestamp"] = _ahora_iso()
            await _enviar_json_seguro(self._ws, self._envio_lock, respuesta)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Inferencia YOLO RTSP omitida en fotograma actual: %s", exc)

    async def _bucle_emision(self, capturador: CapturadorRTSP) -> None:
        """Lee fotogramas RTSP en hilo trabajador, lanza YOLO si hay cerco y emite métricas."""
        try:
            while capturador.activo:
                fotograma = await asyncio.to_thread(capturador.leer_fotograma)
                if fotograma is None:
                    if capturador.activo:
                        await asyncio.to_thread(capturador.detener)
                        await _enviar_json_seguro(
                            self._ws,
                            self._envio_lock,
                            {
                                "tipo": "error_camara",
                                "mensaje": "Se interrumpió la señal de video de la cámara en red.",
                                "timestamp": _ahora_iso(),
                            },
                        )
                    break

                self._programar_yolo_si_aplica(fotograma.frame_bgr)
                inf_ms = (
                    self._ultima_inferencia_ms
                    if self._cerco.esta_cerrado and self._ultima_inferencia_ms > 0.0
                    else fotograma.inferencia_ms
                )
                peatones = self._ultimos_peatones if self._cerco.esta_cerrado else 0

                await _enviar_json_seguro(
                    self._ws,
                    self._envio_lock,
                    {
                        "tipo": "fotograma_rtsp",
                        "frame_b64": fotograma.jpeg_b64,
                        "ancho": fotograma.ancho,
                        "alto": fotograma.alto,
                        "metricas": {
                            "fps": fotograma.fps,
                            "inferencia_ms": round(inf_ms, 2),
                            "area_cerco_pct": self._cerco.calcular_porcentaje_area(),
                            "cpu_pct": fotograma.cpu_pct,
                            "ram_mb": fotograma.ram_mb,
                            "peatones": peatones,
                            "alertas": 0,
                        },
                        "timestamp": _ahora_iso(),
                    },
                )
                await asyncio.sleep(_INTERVALO_FRAME_RTSP_SEG)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Bucle de transmisión RTSP detenido: %s", exc)
            await asyncio.to_thread(capturador.detener)


async def _validar_sesion_ws(
    websocket: WebSocket, token: Optional[str]
) -> Optional[dict[str, Any]]:
    """Valida el token JWT de la sesión única recibido por query param."""
    if not token or not token.strip():
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Token de sesión requerido para monitoreo.",
        )
        return None

    gestor: Optional[GestorSesionUnica] = getattr(
        websocket.app.state, "gestor_sesion", None
    )
    if gestor is None:
        await websocket.close(
            code=status.WS_1011_INTERNAL_ERROR,
            reason="Gestor de sesión no inicializado en el servidor.",
        )
        return None

    usuario = gestor.verificarSesionUnicaActiva(token.strip())
    if not usuario:
        logger.warning("Conexión WebSocket rechazada por token inválido o no coincidente.")
        await websocket.close(
            code=status.WS_1008_POLICY_VIOLATION,
            reason="Sesión inválida, expirada o revocada.",
        )
        return None

    return {"usuario": usuario}


async def _manejar_procesar_frame(
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    data: dict[str, Any],
    cerco_activo: CercoVirtualEnMemoria,
    estrategia_cerco: EstrategiaCercoVirtual,
    detector: IDetectorPeatones,
) -> None:
    """Procesa un fotograma entrante (cámara local PC) ejecutando YOLO en CPU (US-04)."""
    if not cerco_activo.esta_cerrado:
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {
                "tipo": "resultado_deteccion",
                "cerco_activo": False,
                "detecciones": [],
                "peatones_detectados": 0,
                "inferencia_ms": 0.0,
                "area_cerco_pct": 0.0,
                "imgsz": 0,
                "dispositivo": detector.dispositivo,
                "timestamp": _ahora_iso(),
            },
        )
        return

    frame_b64 = data.get("frame_b64", "")
    try:
        ancho_hint = int(data.get("ancho", 640))
        alto_hint = int(data.get("alto", 480))
    except (TypeError, ValueError):
        ancho_hint, alto_hint = 640, 480

    try:
        imagen = decodificar_frame_base64(
            frame_b64=frame_b64,
            ancho_fallback=ancho_hint,
            alto_fallback=alto_hint,
        )
    except FrameInvalidoError as err:
        logger.warning("Fotograma inválido rechazado en /ws/monitoreo: %s", err)
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {
                "tipo": "error_procesamiento",
                "mensaje": str(err),
                "timestamp": _ahora_iso(),
            },
        )
        return

    resultado = await ejecutar_inferencia_cpu(
        estrategia_cerco.procesar,
        imagen,
        cerco_activo,
        detector,
    )
    respuesta = resultado.to_dict()
    respuesta["tipo"] = "resultado_deteccion"
    respuesta["timestamp"] = _ahora_iso()
    await _enviar_json_seguro(websocket, envio_lock, respuesta)


async def _manejar_cerco_actualizado(
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    cerco_activo: CercoVirtualEnMemoria,
    raw_vertices: Any,
) -> None:
    """Procesa y valida la definición o reajuste del cerco de 4 a 6 vértices (RF-04 a RF-06)."""
    try:
        cerco_activo.definir_vertices(raw_vertices if isinstance(raw_vertices, list) else [])
        area_pct = cerco_activo.calcular_porcentaje_area()
        logger.info(
            "Cerco virtual actualizado en memoria: %d vértices, %.2f%% de área",
            cerco_activo.cantidad_vertices,
            area_pct,
        )
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {
                "tipo": "cerco_confirmado",
                "cantidad_vertices": cerco_activo.cantidad_vertices,
                "area_cerco_pct": area_pct,
                "estado": cerco_activo.estado.value,
                "timestamp": _ahora_iso(),
            },
        )
    except CercoInvalidoError as err:
        logger.warning("Intento de trazado de cerco inválido rechazado: %s", err)
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {
                "tipo": "error_cerco",
                "mensaje": str(err),
                "cantidad_vertices_recibidos": len(raw_vertices)
                if isinstance(raw_vertices, list)
                else 0,
                "timestamp": _ahora_iso(),
            },
        )


async def _despachar_evento_ws(
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    cerco_activo: CercoVirtualEnMemoria,
    estrategia_cerco: EstrategiaCercoVirtual,
    detector: IDetectorPeatones,
    gestor_rtsp: _GestorStreamRTSPSesion,
    data: dict[str, Any],
) -> None:
    """Enruta cada mensaje JSON entrante del cliente hacia su manejador específico."""
    tipo_mensaje = data.get("tipo")

    if tipo_mensaje == "ping":
        await _enviar_json_seguro(
            websocket, envio_lock, {"tipo": "pong", "timestamp": _ahora_iso()}
        )
        return

    if tipo_mensaje == "camara_estado":
        estado = data.get("estado", "desconectada")
        logger.info("Estado de cámara local reportado por el cliente: %s", estado)
        if estado == "desconectada":
            await gestor_rtsp.detener(notificar_cliente=False)
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {"tipo": "camara_estado_ack", "estado": estado, "timestamp": _ahora_iso()},
        )
        return

    if tipo_mensaje == "iniciar_rtsp":
        await gestor_rtsp.iniciar(str(data.get("url") or ""))
        return

    if tipo_mensaje == "detener_rtsp":
        await gestor_rtsp.detener(notificar_cliente=True)
        return

    if tipo_mensaje == "cerco_actualizado":
        await _manejar_cerco_actualizado(
            websocket, envio_lock, cerco_activo, data.get("vertices", [])
        )
        return

    if tipo_mensaje == "limpiar_cerco":
        cerco_activo.limpiar()
        gestor_rtsp.reiniciar_telemetria_cerco()
        logger.info("Cerco virtual limpiado en memoria de sesión activa.")
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {"tipo": "cerco_limpiado", "area_cerco_pct": 0.0, "timestamp": _ahora_iso()},
        )
        return

    if tipo_mensaje == "procesar_frame":
        await _manejar_procesar_frame(
            websocket=websocket,
            envio_lock=envio_lock,
            data=data,
            cerco_activo=cerco_activo,
            estrategia_cerco=estrategia_cerco,
            detector=detector,
        )
        return

    await _enviar_json_seguro(
        websocket,
        envio_lock,
        {"tipo": "ack", "recibido": tipo_mensaje, "timestamp": _ahora_iso()},
    )


@router.websocket("/ws/monitoreo")
async def websocket_monitoreo(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """Canal WebSocket en tiempo real para Monitoreo en Vivo (US-02 / US-03 / US-04).

    Mantiene en memoria el cerco virtual activo durante la conexión, soporta cámara local
    y enlaces RTSP/IP, y ejecuta detección YOLO en CPU dentro del área vigilada.
    """
    sesion = await _validar_sesion_ws(websocket, token)
    if sesion is None:
        return

    await websocket.accept()
    usuario = sesion.get("usuario", "operador")
    logger.info("Canal WebSocket /ws/monitoreo abierto para el usuario: %s", usuario)

    envio_lock = asyncio.Lock()
    cerco_activo = CercoVirtualEnMemoria()
    estrategia_cerco = _crear_estrategia_cerco_ws(websocket)
    detector = _obtener_detector_ws(websocket)
    capturador_factory: Callable[[str], CapturadorRTSP] = getattr(
        websocket.app.state, "rtsp_capturador_factory", CapturadorRTSP
    )
    gestor_rtsp = _GestorStreamRTSPSesion(
        websocket=websocket,
        envio_lock=envio_lock,
        cerco_activo=cerco_activo,
        estrategia_cerco=estrategia_cerco,
        detector=detector,
        capturador_factory=capturador_factory,
    )

    await _enviar_json_seguro(
        websocket,
        envio_lock,
        {
            "tipo": "conexion_establecida",
            "usuario": usuario,
            "timestamp": _ahora_iso(),
            "telemetria_inicial": {
                "fps": 0.0,
                "inferencia_ms": 0.0,
                "area_cerco_pct": 0.0,
                "cpu_pct": 0.0,
                "ram_mb": 0.0,
                "peatones": 0,
                "alertas": 0,
            },
        },
    )

    try:
        while True:
            mensaje_raw = await websocket.receive_text()
            try:
                data = json.loads(mensaje_raw)
            except json.JSONDecodeError:
                await _enviar_json_seguro(
                    websocket,
                    envio_lock,
                    {"tipo": "error", "mensaje": "Formato de mensaje JSON inválido."},
                )
                continue

            await _despachar_evento_ws(
                websocket=websocket,
                envio_lock=envio_lock,
                cerco_activo=cerco_activo,
                estrategia_cerco=estrategia_cerco,
                detector=detector,
                gestor_rtsp=gestor_rtsp,
                data=data,
            )
    except WebSocketDisconnect:
        logger.info("Canal WebSocket /ws/monitoreo desconectado por el cliente.")
    except Exception as exc:
        logger.error("Error inesperado en WebSocket /ws/monitoreo: %s", exc)
    finally:
        await gestor_rtsp.detener(notificar_cliente=False)
