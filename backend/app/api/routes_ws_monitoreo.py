"""Router y controlador WebSocket para Monitoreo en Vivo (US-02 / US-03 / US-04).

Gobierna el canal bidireccional /ws/monitoreo con autenticación obligatoria
por token JWT, handshake de estado de cámara, ciclo de vida del cerco virtual en memoria,
aislamiento espacial pre-inferencia (RNF-02) y detección de peatones con YOLO en CPU y RAM
(RF-03, RF-04, RF-05, RF-06, RF-07, RNF-01, RNF-04, CP-02, CP-03, CP-04).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.concurrency import ejecutar_inferencia_cpu
from backend.app.core.config import Settings
from backend.app.domain.cerco_virtual import (
    CercoInvalidoError,
    CercoVirtualEnMemoria,
)
from backend.app.domain.ports import IDetectorPeatones
from backend.app.vision.estrategias_roi import EstrategiaCercoVirtual
from backend.app.vision.yolo_detector import (
    DetectorYOLOCPU,
    FrameInvalidoError,
    decodificar_frame_base64,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Monitoreo en Vivo"])


def _obtener_detector_ws(websocket: WebSocket) -> IDetectorPeatones:
    """Resuelve la instancia del detector YOLO en CPU desde el estado de la app o el Singleton.

    Args:
        websocket: Conexión WebSocket activa.

    Returns:
        Instancia de `IDetectorPeatones` configurada en CPU y memoria RAM.
    """
    detector_inyectado: Optional[IDetectorPeatones] = getattr(
        websocket.app.state, "detector_yolo", None
    )
    if detector_inyectado is not None:
        return detector_inyectado

    settings: Optional[Settings] = getattr(websocket.app.state, "settings", None)
    model_path = settings.yolo_model_path if settings is not None else "models/yolo11n.pt"
    return DetectorYOLOCPU.obtener_instancia(model_path=model_path)


def _crear_estrategia_cerco_ws(websocket: WebSocket) -> EstrategiaCercoVirtual:
    """Construye la estrategia de aislamiento espacial ROI según la configuración activa.

    Args:
        websocket: Conexión WebSocket activa.

    Returns:
        Instancia de `EstrategiaCercoVirtual` con padding RNF-02 e `imgsz` dinámico.
    """
    settings: Optional[Settings] = getattr(websocket.app.state, "settings", None)
    if settings is not None:
        return EstrategiaCercoVirtual(
            padding_pct=settings.roi_padding_pct,
            imgsz_max=settings.yolo_imgsz_max,
            conf_min=settings.yolo_conf_threshold,
        )
    return EstrategiaCercoVirtual()


async def _validar_sesion_ws(
    websocket: WebSocket, token: Optional[str]
) -> Optional[dict[str, Any]]:
    """Valida el token JWT de la sesión única recibido por query param o encabezado."""
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
    data: dict[str, Any],
    cerco_activo: CercoVirtualEnMemoria,
    estrategia_cerco: EstrategiaCercoVirtual,
    detector: IDetectorPeatones,
) -> None:
    """Procesa un fotograma entrante ejecutando YOLO en CPU sobre el área del cerco (US-04).

    Args:
        websocket: Canal WebSocket activo.
        data: Diccionario JSON recibido con `frame_b64` y dimensiones opcionales.
        cerco_activo: Cerco virtual dinámico de 4 a 6 vértices en memoria de sesión.
        estrategia_cerco: Estrategia de recorte con padding RNF-02 y filtro Point-in-Polygon.
        detector: Adaptador de detección YOLO sobre CPU y RAM.
    """
    if not cerco_activo.esta_cerrado:
        await websocket.send_json(
            {
                "tipo": "resultado_deteccion",
                "cerco_activo": False,
                "detecciones": [],
                "peatones_detectados": 0,
                "inferencia_ms": 0.0,
                "area_cerco_pct": 0.0,
                "imgsz": 0,
                "dispositivo": detector.dispositivo,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
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
        await websocket.send_json(
            {
                "tipo": "error_procesamiento",
                "mensaje": str(err),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
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
    respuesta["timestamp"] = datetime.now(timezone.utc).isoformat()
    await websocket.send_json(respuesta)


@router.websocket("/ws/monitoreo")
async def websocket_monitoreo(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """Canal WebSocket en tiempo real para Monitoreo en Vivo (RF-03 a RF-07 / CP-02 a CP-04).

    Mantiene en memoria el cerco virtual activo durante la conexión sin persistencia en base de datos
    y ejecuta la detección de peatones con YOLO sobre CPU y RAM cuando el cerco está cerrado.
    """
    sesion = await _validar_sesion_ws(websocket, token)
    if sesion is None:
        return

    await websocket.accept()
    usuario = sesion.get("usuario", "operador")
    logger.info("Canal WebSocket /ws/monitoreo abierto para el usuario: %s", usuario)

    # Cerco virtual dinámico efímero en memoria (RNF-04 / cero persistencia en BD)
    cerco_activo = CercoVirtualEnMemoria()
    estrategia_cerco = _crear_estrategia_cerco_ws(websocket)
    detector = _obtener_detector_ws(websocket)

    # Enviar mensaje de bienvenida y telemetría inicial
    await websocket.send_json(
        {
            "tipo": "conexion_establecida",
            "usuario": usuario,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "telemetria_inicial": {
                "fps": 0.0,
                "inferencia_ms": 0.0,
                "area_cerco_pct": 0.0,
                "cpu_pct": 0.0,
                "ram_mb": 0.0,
                "peatones": 0,
                "alertas": 0,
            },
        }
    )

    try:
        while True:
            mensaje_raw = await websocket.receive_text()
            try:
                data = json.loads(mensaje_raw)
            except json.JSONDecodeError:
                await websocket.send_json(
                    {"tipo": "error", "mensaje": "Formato de mensaje JSON inválido."}
                )
                continue

            tipo_mensaje = data.get("tipo")

            if tipo_mensaje == "ping":
                await websocket.send_json(
                    {
                        "tipo": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            elif tipo_mensaje == "camara_estado":
                estado = data.get("estado", "desconectada")
                logger.info("Estado de cámara reportado por el cliente: %s", estado)
                await websocket.send_json(
                    {
                        "tipo": "camara_estado_ack",
                        "estado": estado,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            elif tipo_mensaje == "cerco_actualizado":
                # Definición o reajuste dinámico del cerco de 4 a 6 vértices (RF-04 / RF-05 / RF-06 / CP-03)
                raw_vertices = data.get("vertices", [])
                try:
                    cerco_activo.definir_vertices(raw_vertices)
                    area_pct = cerco_activo.calcular_porcentaje_area()
                    logger.info(
                        "Cerco virtual actualizado en memoria: %d vértices, %.2f%% de área",
                        cerco_activo.cantidad_vertices,
                        area_pct,
                    )
                    await websocket.send_json(
                        {
                            "tipo": "cerco_confirmado",
                            "cantidad_vertices": cerco_activo.cantidad_vertices,
                            "area_cerco_pct": area_pct,
                            "estado": cerco_activo.estado.value,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                except CercoInvalidoError as err:
                    logger.warning("Intento de trazado de cerco inválido rechazado: %s", err)
                    await websocket.send_json(
                        {
                            "tipo": "error_cerco",
                            "mensaje": str(err),
                            "cantidad_vertices_recibidos": len(raw_vertices)
                            if isinstance(raw_vertices, list)
                            else 0,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )

            elif tipo_mensaje == "limpiar_cerco":
                # Limpieza del lienzo en caliente (RF-06)
                cerco_activo.limpiar()
                logger.info("Cerco virtual limpiado en memoria de sesión activa.")
                await websocket.send_json(
                    {
                        "tipo": "cerco_limpiado",
                        "area_cerco_pct": 0.0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            elif tipo_mensaje == "procesar_frame":
                # Ejecución de YOLO sobre el área del cerco en CPU y memoria RAM (US-04 / RF-07 / RNF-01 / RNF-02)
                await _manejar_procesar_frame(
                    websocket=websocket,
                    data=data,
                    cerco_activo=cerco_activo,
                    estrategia_cerco=estrategia_cerco,
                    detector=detector,
                )

            else:
                await websocket.send_json(
                    {
                        "tipo": "ack",
                        "recibido": tipo_mensaje,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

    except WebSocketDisconnect:
        logger.info("Canal WebSocket /ws/monitoreo desconectado por el cliente.")
    except Exception as exc:
        logger.error("Error inesperado en WebSocket /ws/monitoreo: %s", exc)
