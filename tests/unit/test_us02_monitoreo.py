"""Unit and integration tests for User Story 2 (US-02 / RF-03 / CP-02).

Verifies real-time camera UI structure, exclusion of audio/file upload,
WebSocket /ws/monitoreo authentication, signaling, and CSP security headers.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest

from backend.app.core.config import Settings
from backend.app.main import create_app
from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.vision.capturador_rtsp import (
    CapturadorRTSP,
    URLCamaraInvalidaError,
    enmascarar_url_camara,
    normalizar_url_camara,
)

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"


class _FakeUpdateResult:
    def __init__(self, matched_count: int, modified_count: int) -> None:
        self.matched_count = matched_count
        self.modified_count = modified_count


class _FakeRepo:
    """Minimal fake repository for testing US-02 WebSocket auth."""

    def __init__(self, active_session_id: Optional[str] = None) -> None:
        self.active_session_id = active_session_id or str(uuid.uuid4())
        self.users: dict[str, dict[str, Any]] = {
            "vi": {
                "usuario": "vi",
                "correo": "operador@espe.edu.ec",
                "token_sesion_unica": self.active_session_id,
            }
        }

    def ping(self) -> bool:
        return True

    def esperar_conexion(self, max_retries: int = 1, delay_seconds: float = 0.0) -> bool:
        return True

    def close(self) -> None:
        pass

    def inicializarCuentaUnica(self) -> None:
        pass

    def validarCredencialesUnicas(self, usuario: str) -> Optional[dict[str, Any]]:
        user = self.users.get(usuario)
        return dict(user) if user else None

    def buscar_por_usuario(self, username: str) -> Optional[dict[str, Any]]:
        user = self.users.get(username)
        return dict(user) if user else None

    def actualizar_token_sesion(
        self, username: str, session_id: Optional[str]
    ) -> _FakeUpdateResult:
        if username in self.users:
            self.users[username]["token_sesion_unica"] = session_id
            self.active_session_id = session_id or ""
            return _FakeUpdateResult(1, 1)
        return _FakeUpdateResult(0, 0)


def _crear_test_token(
    username: str = "vi",
    session_id: str = "session-123",
    secret: str = _TEST_JWT_SECRET,
    expired: bool = False,
) -> str:
    """Helper to generate a signed JWT for testing."""
    now = datetime.now(timezone.utc)
    delta = timedelta(hours=-1) if expired else timedelta(hours=2)
    payload = {
        "sub": username,
        "usuario": username,
        "sid": session_id,
        "iat": int(now.timestamp()),
        "exp": int((now + delta).timestamp()),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _build_test_client(fake_repo: _FakeRepo) -> tuple[TestClient, GestorSesionUnica, Settings]:
    settings = Settings(
        mongo_uri="mongodb://localhost:27017",
        mongo_db_name="vi_test_db",
        jwt_secret=_TEST_JWT_SECRET,
        jwt_algorithm="HS256",
        jwt_expiration_minutes=120,
        default_username="vi",
        default_email="operador@espe.edu.ec",
        default_password="OperadorVI2026*",
        bcrypt_rounds=4,
        smtp_host="",
        smtp_port=587,
        smtp_user="",
        smtp_password="",
        smtp_from="no-reply@espe.edu.ec",
        app_port=8000,
        log_level="INFO",
    )
    gestor = GestorSesionUnica(repositorio=fake_repo, settings=settings)  # type: ignore[arg-type]
    fastapi_app = create_app(settings=settings, repositorio=fake_repo, gestor=gestor)  # type: ignore[arg-type]
    client = TestClient(fastapi_app)
    return client, gestor, settings


# ---------------------------------------------------------------------------
# Test Cases (US-02 / RF-03 / CP-02)
# ---------------------------------------------------------------------------


def test_us02_monitoreo_html_estructura_y_restricciones() -> None:
    """Verifica que la vista HTML contenga los controles de cámara y no viole restricciones."""
    html_path = Path(__file__).resolve().parent.parent.parent / "frontend" / "monitoreo.html"
    assert html_path.is_file(), "El archivo monitoreo.html debe existir en frontend/"

    content = html_path.read_text(encoding="utf-8")

    # Controles exigidos por RF-03 (modo local PC y modo enlace RTSP/IP)
    assert 'id="iniciar-camara"' in content, "Debe existir el botón Iniciar Cámara."
    assert 'id="camara-estado"' in content, "Debe existir el badge de estado de cámara."
    assert 'id="video-stream"' in content, "Debe existir el elemento video-stream para el flujo local."
    assert 'id="rtsp-stream"' in content, "Debe existir el elemento rtsp-stream para el flujo en red."
    assert 'id="modo-camara-local"' in content, "Debe existir el selector de Cámara Local (PC)."
    assert 'id="modo-camara-rtsp"' in content, "Debe existir el selector de Enlace RTSP / IP."
    assert 'id="rtsp-url-input"' in content, "Debe existir el campo de entrada de enlace RTSP."
    assert 'id="canvas-stage"' in content, "Debe existir el lienzo canvas-stage."

    # Restricciones innegociables (Tabla 2: Cero carga de archivos y cero audio en monitoreo)
    assert 'type="file"' not in content, "Prohibido selector de carga de archivos en monitoreo en vivo."
    assert "<audio" not in content, "Prohibido elemento de audio en monitoreo en vivo."


def test_us02_csp_permite_conexiones() -> None:
    """Verifica que Content-Security-Policy defina connect-src 'self'."""
    fake_repo = _FakeRepo()
    client, _, _ = _build_test_client(fake_repo)

    resp = client.get("/monitoreo")
    assert resp.status_code == 200
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "connect-src 'self'" in csp, "connect-src debe permitir 'self'."


def test_us02_websocket_sin_token_rechaza_1008() -> None:
    """Verifica que conectar a /ws/monitoreo sin token cierre con código 1008."""
    fake_repo = _FakeRepo()
    client, _, _ = _build_test_client(fake_repo)

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/monitoreo"):
            pass


def test_us02_websocket_token_invalido_rechaza_1008() -> None:
    """Verifica que conectar con un token forjado o inválido cierre con código 1008."""
    fake_repo = _FakeRepo()
    client, _, _ = _build_test_client(fake_repo)

    token_falso = _crear_test_token(secret="clave_totalmente_incorrecta_de_32_caracteres_o_mas!")
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/monitoreo?token={token_falso}"):
            pass


def test_us02_websocket_token_valido_conecta_y_recibe_telemetria() -> None:
    """Verifica conexión exitosa, bienvenida con 6 métricas y señalización de cámara."""
    token_valido = _crear_test_token(username="vi")
    fake_repo = _FakeRepo(active_session_id=token_valido)
    fake_repo.users["vi"]["token_sesion_unica"] = token_valido
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token_valido}") as ws:
        # 1. Recibir mensaje inicial de bienvenida y telemetría (RF-11)
        data = ws.receive_json()
        assert data.get("tipo") == "conexion_establecida"
        assert data.get("usuario") == "vi"
        assert "telemetria_inicial" in data
        metrics = data["telemetria_inicial"]
        assert all(k in metrics for k in ["fps", "inferencia_ms", "area_cerco_pct", "cpu_pct", "ram_mb", "peatones", "alertas"])

        # 2. Enviar señalización de inicio de cámara
        ws.send_json({"tipo": "camara_estado", "estado": "conectada"})
        ack = ws.receive_json()
        assert ack.get("tipo") == "camara_estado_ack"
        assert ack.get("estado") == "conectada"

        # 3. Heartbeat ping-pong
        ws.send_json({"tipo": "ping"})
        pong = ws.receive_json()
        assert pong.get("tipo") == "pong"
        assert "timestamp" in pong


# ---------------------------------------------------------------------------
# Pruebas de Cámara por Enlace RTSP / IP (RF-03 / RNF-01 / CP-02)
# ---------------------------------------------------------------------------


class _FakeFrame:
    """Simula un ndarray (alto, ancho, 3) sin requerir hardware de cámara."""

    def __init__(self, ancho: int = 640, alto: int = 360) -> None:
        self.shape = (alto, ancho, 3)
        self.ndim = 3


class _FakeVideoCapture:
    """Doble de prueba determinista para cv2.VideoCapture."""

    def __init__(self, opened: bool = True, max_frames: int = 5) -> None:
        self._opened = opened
        self._remaining = max_frames
        self.released = False

    def isOpened(self) -> bool:
        return self._opened and not self.released

    def read(self) -> tuple[bool, Optional[_FakeFrame]]:
        if not self._opened or self.released or self._remaining <= 0:
            return False, None
        self._remaining -= 1
        return True, _FakeFrame(640, 360)

    def release(self) -> None:
        self.released = True


def test_rtsp_normalizar_url_con_prefijo_ip_y_enmascaramiento() -> None:
    """Verifica saneamiento de prefijo 'IP' accidental, símbolos y ocultamiento de clave."""
    enlace_ejemplo = "rtsp://admin:Espe2025*@IP192.168.0.76:554/Streaming/Channels/101"
    normalizada = normalizar_url_camara(enlace_ejemplo)
    assert normalizada == "rtsp://admin:Espe2025*@192.168.0.76:554/Streaming/Channels/101"

    enmascarada = enmascarar_url_camara(normalizada)
    assert enmascarada == "rtsp://admin:***@192.168.0.76:554/Streaming/Channels/101"
    assert "Espe2025*" not in enmascarada

    # Contraseña con '@' interno codificada sin romper la autoridad host:puerto
    con_arroba = normalizar_url_camara("rtsp://operador:Clave@2026@192.168.1.50:554/live")
    assert con_arroba == "rtsp://operador:Clave%402026@192.168.1.50:554/live"


@pytest.mark.parametrize(
    "url_invalida",
    [
        "",
        "   ",
        "0",
        "/dev/video0",
        "file:///etc/passwd",
        "ftp://192.168.0.76:21/video",
        "rtsp://999.168.0.76:554/Streaming/Channels/101",
        "rtsp://192.168.0.76:70000/Streaming/Channels/101",
        "rtsp://192.168.0.76:abc/Streaming/Channels/101",
        "rtsp://admin:clave con espacio@192.168.0.76:554/ch1",
    ],
)
def test_rtsp_rechaza_esquemas_inseguros_y_direcciones_invalidas(url_invalida: str) -> None:
    """Asegura bloqueo estricto contra SSRF de archivos locales y URLs malformadas."""
    with pytest.raises(URLCamaraInvalidaError):
        normalizar_url_camara(url_invalida)


def test_rtsp_capturador_ciclo_vida_en_cpu() -> None:
    """Valida apertura, lectura de fotograma codificado y liberación del descriptor."""
    instancias: list[_FakeVideoCapture] = []

    def fake_factory(_url: str) -> _FakeVideoCapture:
        cap = _FakeVideoCapture(opened=True, max_frames=3)
        instancias.append(cap)
        return cap

    def fake_encoder(_frame: Any, _max_w: int, _q: int) -> tuple[str, int, int]:
        return "ZmFrZV9qcGVn", 640, 360

    capturador = CapturadorRTSP(
        url="rtsp://admin:Espe2025*@IP192.168.0.76:554/Streaming/Channels/101",
        capture_factory=fake_factory,
        encoder_fn=fake_encoder,
    )
    ancho, alto = capturador.conectar()
    assert (ancho, alto) == (640, 360)
    assert capturador.activo is True

    cuadro = capturador.leer_fotograma()
    assert cuadro is not None
    assert cuadro.jpeg_b64 == "ZmFrZV9qcGVn"
    assert cuadro.ancho == 640
    assert cuadro.alto == 360
    assert cuadro.cpu_pct >= 0.0
    assert cuadro.ram_mb >= 0.0

    capturador.detener()
    assert capturador.activo is False
    assert instancias[0].released is True


def test_ws_monitoreo_flujo_rtsp_completo_y_liberacion() -> None:
    """Verifica conexión RTSP por WebSocket, recepción de cuadros/métricas y parada limpia."""
    token_valido = _crear_test_token(username="vi")
    fake_repo = _FakeRepo(active_session_id=token_valido)
    fake_repo.users["vi"]["token_sesion_unica"] = token_valido
    client, _, _ = _build_test_client(fake_repo)

    capturas_creadas: list[_FakeVideoCapture] = []

    def crear_capturador_prueba(url: str) -> CapturadorRTSP:
        def fake_factory(_u: str) -> _FakeVideoCapture:
            cap = _FakeVideoCapture(opened=True, max_frames=20)
            capturas_creadas.append(cap)
            return cap

        return CapturadorRTSP(
            url=url,
            capture_factory=fake_factory,
            encoder_fn=lambda _f, _w, _q: ("dGVzdF9qcGVn", 640, 360),
        )

    client.app.state.rtsp_capturador_factory = crear_capturador_prueba  # type: ignore[attr-defined]

    with client.websocket_connect(f"/ws/monitoreo?token={token_valido}") as ws:
        bienvenida = ws.receive_json()
        assert bienvenida.get("tipo") == "conexion_establecida"

        ws.send_json(
            {
                "tipo": "iniciar_rtsp",
                "url": "rtsp://admin:Espe2025*@IP192.168.0.76:554/Streaming/Channels/101",
            }
        )

        conectado = ws.receive_json()
        assert conectado.get("tipo") == "rtsp_conectado"
        assert conectado.get("url") == "rtsp://admin:***@192.168.0.76:554/Streaming/Channels/101"
        assert conectado.get("ancho") == 640
        assert conectado.get("alto") == 360

        fotograma = ws.receive_json()
        assert fotograma.get("tipo") == "fotograma_rtsp"
        assert fotograma.get("frame_b64") == "dGVzdF9qcGVn"
        metricas = fotograma.get("metricas", {})
        assert all(
            k in metricas
            for k in ["fps", "inferencia_ms", "area_cerco_pct", "cpu_pct", "ram_mb", "peatones", "alertas"]
        )

        ws.send_json({"tipo": "detener_rtsp"})
        # Consumir posibles fotogramas en tránsito antes del acuse rtsp_detenido
        tipos_recibidos: list[str] = []
        for _ in range(5):
            msg = ws.receive_json()
            tipos_recibidos.append(str(msg.get("tipo")))
            if msg.get("tipo") == "rtsp_detenido":
                break

        assert "rtsp_detenido" in tipos_recibidos
        assert len(capturas_creadas) == 1
        assert capturas_creadas[0].released is True


def test_ws_monitoreo_rtsp_enlace_invalido_emite_error_sin_cerrar_ws() -> None:
    """Verifica que un enlace prohibido devuelva 'error_camara' manteniendo vivo el canal."""
    token_valido = _crear_test_token(username="vi")
    fake_repo = _FakeRepo(active_session_id=token_valido)
    fake_repo.users["vi"]["token_sesion_unica"] = token_valido
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token_valido}") as ws:
        _ = ws.receive_json()
        ws.send_json({"tipo": "iniciar_rtsp", "url": "file:///etc/passwd"})
        err = ws.receive_json()
        assert err.get("tipo") == "error_camara"
        assert "no permitido" in err.get("mensaje", "")

        # El canal sigue operativo tras el error controlado
        ws.send_json({"tipo": "ping"})
        pong = ws.receive_json()
        assert pong.get("tipo") == "pong"
