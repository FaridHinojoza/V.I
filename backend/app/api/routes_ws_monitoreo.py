"""Router y controlador WebSocket para Monitoreo en Vivo (US-02 / US-03 / US-04 / US-05).

Gobierna el canal bidireccional /ws/monitoreo con autenticación obligatoria
por token JWT, soporte dual para cámara local (PC) o enlace de cámara en red (RTSP / IP),
ciclo de vida del cerco virtual en memoria, detección YOLO + seguimiento ByteTrack en CPU/RAM
y emisión continua de las 8 métricas computacionales de V 1.2 (RF-03 a RF-08, RF-11, CP-02 a CP-04).
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
from backend.app.core.telemetry import MonitorTelemetriaProceso
from backend.app.domain.cerco_virtual import (
    CercoInvalidoError,
    CercoVirtualEnMemoria,
)
from backend.app.domain.metricas import MetricasOperativas
from backend.app.domain.ports import IDetectorPeatones, IRastreadorPeatones
from backend.app.vision.capturador_rtsp import (
    CapturadorRTSP,
    URLCamaraInvalidaError,
)
from backend.app.vision.estrategias_roi import EstrategiaCercoVirtual
from backend.app.vision.tracker_bytetrack import RastreadorByteTrack
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
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    payload: dict[str, Any],
    monitor_telemetria: Optional[MonitorTelemetriaProceso] = None,
    contabilizar_bytes: bool = True,
) -> None:
    """Serializa el envío por WebSocket y registra los bytes salientes para KB/s (RF-11)."""
    texto = json.dumps(payload, ensure_ascii=False)
    if contabilizar_bytes and monitor_telemetria is not None:
        monitor_telemetria.registrar_bytes_payload(len(texto.encode("utf-8")))
    async with envio_lock:
        await websocket.send_text(texto)


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


def _crear_rastreador_ws(websocket: WebSocket) -> IRastreadorPeatones:
    """Instancia un rastreador ByteTrack aislado para la sesión WebSocket activa."""
    fabrica: Optional[Callable[[], IRastreadorPeatones]] = getattr(
        websocket.app.state, "rastreador_factory", None
    )
    if fabrica is not None:
        return fabrica()

    settings: Optional[Settings] = getattr(websocket.app.state, "settings", None)
    conf_alta = settings.yolo_conf_threshold if settings is not None else 0.35
    return RastreadorByteTrack(conf_alta=conf_alta)


class _GestorStreamRTSPSesion:
    """Administra la captura RTSP, seguimiento ByteTrack y las 8 métricas sobre CPU/RAM."""

    def __init__(
        self,
        websocket: WebSocket,
        envio_lock: asyncio.Lock,
        cerco_activo: CercoVirtualEnMemoria,
        estrategia_cerco: EstrategiaCercoVirtual,
        detector: IDetectorPeatones,
        rastreador: IRastreadorPeatones,
        monitor_telemetria: MonitorTelemetriaProceso,
        capturador_factory: Callable[[str], CapturadorRTSP],
    ) -> None:
        self._ws = websocket
        self._envio_lock = envio_lock
        self._cerco = cerco_activo
        self._estrategia = estrategia_cerco
        self._detector = detector
        self._rastreador = rastreador
        self._telemetria = monitor_telemetria
        self._factory = capturador_factory
        self._capturador: Optional[CapturadorRTSP] = None
        self._tarea_emision: Optional[asyncio.Task[None]] = None
        self._tarea_yolo: Optional[asyncio.Task[None]] = None
        self._ultimo_disparo_yolo: float = 0.0
        self._ultima_inferencia_ms: float = 0.0
        self._ultimos_peatones: int = 0
        self._ultimo_fps_rtsp: float = 0.0

    def reiniciar_telemetria_cerco(self) -> None:
        """Limpia contadores de inferencia y pistas ByteTrack cuando se borra el cerco."""
        self._ultima_inferencia_ms = 0.0
        self._ultimos_peatones = 0
        self._rastreador.reiniciar()

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
                self._telemetria,
            )
            return

        self._capturador = capturador
        self._telemetria.reiniciar()
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
            self._telemetria,
        )
        self._tarea_emision = asyncio.create_task(self._bucle_emision(capturador))

    async def detener(self, notificar_cliente: bool = False) -> None:
        """Cancela tareas de captura/inferencia, reinicia pistas y libera OpenCV."""
        capturador = self._capturador
        tarea_emision = self._tarea_emision
        tarea_yolo = self._tarea_yolo
        self._capturador = None
        self._tarea_emision = None
        self._tarea_yolo = None
        self.reiniciar_telemetria_cerco()
        self._telemetria.reiniciar()

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
                self._telemetria,
            )

    def _programar_yolo_si_aplica(self, frame_bgr: Any) -> None:
        """Lanza detección YOLO + ByteTrack con backpressure sin frenar el video RTSP."""
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
        """Ejecuta EstrategiaCercoVirtual + ByteTrack sobre el cuadro BGR en memoria."""
        try:
            resultado = await ejecutar_inferencia_cpu(
                self._estrategia.procesar,
                frame_bgr,
                self._cerco,
                self._detector,
                self._rastreador,
            )
            if self._capturador is None or not self._capturador.activo:
                return

            self._ultima_inferencia_ms = float(resultado.inferencia_ms)
            self._ultimos_peatones = int(resultado.peatones_detectados)
            respuesta = resultado.to_dict()
            respuesta["tipo"] = "resultado_deteccion"
            respuesta["metricas"] = self._telemetria.construir_metricas(
                inferencia_ms=resultado.inferencia_ms,
                area_cerco_pct=resultado.area_cerco_pct,
                peatones=resultado.peatones_detectados,
                alertas=0,
                fps_override=self._ultimo_fps_rtsp,
            ).to_dict()
            respuesta["timestamp"] = _ahora_iso()
            await _enviar_json_seguro(
                self._ws, self._envio_lock, respuesta, self._telemetria
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Inferencia YOLO+ByteTrack RTSP omitida en fotograma: %s", exc)

    async def _bucle_emision(self, capturador: CapturadorRTSP) -> None:
        """Lee fotogramas RTSP, registra payload KB/s y emite las 8 métricas (RF-11)."""
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
                            self._telemetria,
                        )
                    break

                self._ultimo_fps_rtsp = fotograma.fps
                self._programar_yolo_si_aplica(fotograma.frame_bgr)
                inf_ms = (
                    self._ultima_inferencia_ms
                    if self._cerco.esta_cerrado and self._ultima_inferencia_ms > 0.0
                    else fotograma.inferencia_ms
                )
                peatones = self._ultimos_peatones if self._cerco.esta_cerrado else 0

                # Contabilizar bytes estimados del fotograma saliente para reportar KB/s inmediatos
                kbs_actual = self._telemetria.registrar_bytes_payload(
                    len(fotograma.jpeg_b64) + 260
                )
                metricas_frame = MetricasOperativas(
                    fps=fotograma.fps,
                    inferencia_ms=round(inf_ms, 2),
                    area_cerco_pct=self._cerco.calcular_porcentaje_area(),
                    cpu_pct=fotograma.cpu_pct,
                    ram_mb=fotograma.ram_mb,
                    gpu_pct=fotograma.gpu_pct,
                    ancho_banda_kbs=kbs_actual,
                    peatones=peatones,
                    alertas=0,
                ).to_dict()

                await _enviar_json_seguro(
                    self._ws,
                    self._envio_lock,
                    {
                        "tipo": "fotograma_rtsp",
                        "frame_b64": fotograma.jpeg_b64,
                        "ancho": fotograma.ancho,
                        "alto": fotograma.alto,
                        "metricas": metricas_frame,
                        "timestamp": _ahora_iso(),
                    },
                    self._telemetria,
                    contabilizar_bytes=False,
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
    rastreador: IRastreadorPeatones,
    monitor_telemetria: MonitorTelemetriaProceso,
) -> None:
    """Procesa un fotograma de cámara local ejecutando YOLO + ByteTrack y las 8 métricas."""
    monitor_telemetria.registrar_fotograma()

    if not cerco_activo.esta_cerrado:
        metricas_sin_cerco = monitor_telemetria.construir_metricas(
            inferencia_ms=0.0,
            area_cerco_pct=0.0,
            peatones=0,
            alertas=0,
        ).to_dict()
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
                "metricas": metricas_sin_cerco,
                "timestamp": _ahora_iso(),
            },
            monitor_telemetria,
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
            monitor_telemetria,
        )
        return

    resultado = await ejecutar_inferencia_cpu(
        estrategia_cerco.procesar,
        imagen,
        cerco_activo,
        detector,
        rastreador,
    )
    respuesta = resultado.to_dict()
    respuesta["tipo"] = "resultado_deteccion"
    respuesta["metricas"] = monitor_telemetria.construir_metricas(
        inferencia_ms=resultado.inferencia_ms,
        area_cerco_pct=resultado.area_cerco_pct,
        peatones=resultado.peatones_detectados,
        alertas=0,
    ).to_dict()
    respuesta["timestamp"] = _ahora_iso()
    await _enviar_json_seguro(websocket, envio_lock, respuesta, monitor_telemetria)


async def _manejar_cerco_actualizado(
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    cerco_activo: CercoVirtualEnMemoria,
    raw_vertices: Any,
    monitor_telemetria: MonitorTelemetriaProceso,
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
            monitor_telemetria,
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
            monitor_telemetria,
        )


async def _despachar_evento_ws(
    websocket: WebSocket,
    envio_lock: asyncio.Lock,
    cerco_activo: CercoVirtualEnMemoria,
    estrategia_cerco: EstrategiaCercoVirtual,
    detector: IDetectorPeatones,
    rastreador: IRastreadorPeatones,
    monitor_telemetria: MonitorTelemetriaProceso,
    gestor_rtsp: _GestorStreamRTSPSesion,
    data: dict[str, Any],
) -> None:
    """Enruta cada mensaje JSON entrante del cliente hacia su manejador específico."""
    tipo_mensaje = data.get("tipo")

    if tipo_mensaje == "ping":
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {"tipo": "pong", "timestamp": _ahora_iso()},
            monitor_telemetria,
        )
        return

    if tipo_mensaje == "camara_estado":
        estado = data.get("estado", "desconectada")
        logger.info("Estado de cámara local reportado por el cliente: %s", estado)
        if estado == "desconectada":
            await gestor_rtsp.detener(notificar_cliente=False)
            rastreador.reiniciar()
            monitor_telemetria.reiniciar()
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {"tipo": "camara_estado_ack", "estado": estado, "timestamp": _ahora_iso()},
            monitor_telemetria,
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
            websocket,
            envio_lock,
            cerco_activo,
            data.get("vertices", []),
            monitor_telemetria,
        )
        return

    if tipo_mensaje == "limpiar_cerco":
        cerco_activo.limpiar()
        rastreador.reiniciar()
        gestor_rtsp.reiniciar_telemetria_cerco()
        logger.info("Cerco virtual y rastreador ByteTrack limpiados en sesión activa.")
        await _enviar_json_seguro(
            websocket,
            envio_lock,
            {"tipo": "cerco_limpiado", "area_cerco_pct": 0.0, "timestamp": _ahora_iso()},
            monitor_telemetria,
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
            rastreador=rastreador,
            monitor_telemetria=monitor_telemetria,
        )
        return

    await _enviar_json_seguro(
        websocket,
        envio_lock,
        {"tipo": "ack", "recibido": tipo_mensaje, "timestamp": _ahora_iso()},
        monitor_telemetria,
    )


@router.websocket("/ws/monitoreo")
async def websocket_monitoreo(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """Canal WebSocket en tiempo real para Monitoreo en Vivo (US-02 a US-05 / V 1.2)."""
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
    rastreador = _crear_rastreador_ws(websocket)
    monitor_telemetria = MonitorTelemetriaProceso()
    capturador_factory: Callable[[str], CapturadorRTSP] = getattr(
        websocket.app.state, "rtsp_capturador_factory", CapturadorRTSP
    )
    gestor_rtsp = _GestorStreamRTSPSesion(
        websocket=websocket,
        envio_lock=envio_lock,
        cerco_activo=cerco_activo,
        estrategia_cerco=estrategia_cerco,
        detector=detector,
        rastreador=rastreador,
        monitor_telemetria=monitor_telemetria,
        capturador_factory=capturador_factory,
    )

    await _enviar_json_seguro(
        websocket,
        envio_lock,
        {
            "tipo": "conexion_establecida",
            "usuario": usuario,
            "timestamp": _ahora_iso(),
            "telemetria_inicial": MetricasOperativas.iniciales().to_dict(),
        },
        monitor_telemetria,
    )

    try:
        while True:
            mensaje_raw = await websocket.receive_text()
            monitor_telemetria.registrar_bytes_payload(len(mensaje_raw.encode("utf-8")))
            try:
                data = json.loads(mensaje_raw)
            except json.JSONDecodeError:
                await _enviar_json_seguro(
                    websocket,
                    envio_lock,
                    {"tipo": "error", "mensaje": "Formato de mensaje JSON inválido."},
                    monitor_telemetria,
                )
                continue

            await _despachar_evento_ws(
                websocket=websocket,
                envio_lock=envio_lock,
                cerco_activo=cerco_activo,
                estrategia_cerco=estrategia_cerco,
                detector=detector,
                rastreador=rastreador,
                monitor_telemetria=monitor_telemetria,
                gestor_rtsp=gestor_rtsp,
                data=data,
            )
    except WebSocketDisconnect:
        logger.info("Canal WebSocket /ws/monitoreo desconectado por el cliente.")
    except Exception as exc:
        logger.error("Error inesperado en WebSocket /ws/monitoreo: %s", exc)
    finally:
        await gestor_rtsp.detener(notificar_cliente=False)
