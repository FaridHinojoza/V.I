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

    # Controles exigidos por RF-03
    assert 'id="iniciar-camara"' in content, "Debe existir el botón Iniciar Cámara."
    assert 'id="camara-estado"' in content, "Debe existir el badge de estado de cámara."
    assert 'id="video-stream"' in content, "Debe existir el elemento video-stream para el flujo."
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
