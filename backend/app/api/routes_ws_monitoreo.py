"""Router y controlador WebSocket para Monitoreo en Vivo (US-02 / RF-03).

Gobierna el canal bidireccional /ws/monitoreo con autenticación obligatoria
por token JWT, handshake de estado de cámara y envío de telemetría base.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from backend.app.application.gestor_sesion import GestorSesionUnica

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Monitoreo en Vivo"])


async def _validar_sesion_ws(
    websocket: WebSocket, token: Optional[str]
) -> Optional[dict[str, Any]]:
    """Valida el token JWT de la sesión única recibido por query param o encabezado.

    Args:
        websocket: Instancia de la conexión WebSocket entrante.
        token: Cadena con el token JWT obtenido del parámetro de consulta.

    Returns:
        Diccionario con el payload verificado de la sesión, o None si es inválido.
    """
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


@router.websocket("/ws/monitoreo")
async def websocket_monitoreo(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """Canal WebSocket en tiempo real para Monitoreo en Vivo (RF-03 / CP-02).

    Establece la comunicación bidireccional para señalización de cámara conectada,
    confirmación de estados y telemetría operativa inicial.

    Args:
        websocket: Objeto WebSocket de FastAPI.
        token: Token JWT de sesión única enviado en la consulta ws://.../ws/monitoreo?token=...
    """
    # 1. Validar autenticación antes de aceptar el handshake
    sesion = await _validar_sesion_ws(websocket, token)
    if sesion is None:
        return

    await websocket.accept()
    usuario = sesion.get("usuario", "operador")
    logger.info("Canal WebSocket /ws/monitoreo abierto para el usuario: %s", usuario)

    # 2. Enviar mensaje de bienvenida y estado inicial de telemetría (RF-11)
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
            # Escucha continua de mensajes enviados desde el cliente web
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
                # Heartbeat para evitar timeout de conexión del navegador
                await websocket.send_json(
                    {
                        "tipo": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            elif tipo_mensaje == "camara_estado":
                # Señalización de inicio o detención del flujo de la cámara en vivo
                estado = data.get("estado", "desconectada")
                logger.info("Estado de cámara reportado por el cliente: %s", estado)
                await websocket.send_json(
                    {
                        "tipo": "camara_estado_ack",
                        "estado": estado,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

            else:
                # Responder confirmación para mensajes genéricos
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
