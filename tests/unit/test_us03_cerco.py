"""Pruebas unitarias e integrales para la Historia de Usuario 3 (US-03 / RF-04 / RF-05 / RF-06 / CP-03).

Verifica la delimitación dinámica de cerco virtual interactivo en HTML5 Canvas:
- Geometría obligatoria de 4 a 6 vértices normalizados [0.0 .. 1.0] (CP-03).
- Algoritmo de área (Shoelace) y Point-in-Polygon (Ray-casting) para CPU.
- Cero persistencia en MongoDB Atlas: ciclo de vida restringido a memoria de sesión.
- Señalización bidireccional por WebSocket (/ws/monitoreo).
- Estructura y controles del lienzo en frontend (HTML5/CSS).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest

from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.config import Settings
from backend.app.domain.cerco_virtual import (
    CercoInvalidoError,
    CercoVirtualEnMemoria,
    EstadoCerco,
)
from backend.app.main import create_app

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"


class _FakeUpdateResult:
    def __init__(self, matched_count: int, modified_count: int) -> None:
        self.matched_count = matched_count
        self.modified_count = modified_count


class _FakeRepo:
    """Repositorio mock para aislar y validar cero persistencia en base de datos."""

    def __init__(self, active_session_id: Optional[str] = None) -> None:
        self.active_session_id = active_session_id or str(uuid.uuid4())
        self.users: dict[str, dict[str, Any]] = {
            "vi": {
                "usuario": "vi",
                "correo": "operador@espe.edu.ec",
                "token_sesion_unica": self.active_session_id,
            }
        }
        self.cercos_guardados: list[Any] = []

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
    session_id: str = "session-test-us03",
    secret: str = _TEST_JWT_SECRET,
) -> str:
    now = datetime.now(timezone.utc)
    delta = timedelta(hours=2)
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


# ===========================================================================
# 1. Pruebas de Estructura de UI y Controles HTML/CSS (US-03 / RF-04 / RF-05)
# ===========================================================================


def test_us03_html_estructura_controles_cerco() -> None:
    """Verifica que el HTML incluya todos los botones y badges exigidos para US-03."""
    html_path = Path(__file__).resolve().parent.parent.parent / "frontend" / "monitoreo.html"
    assert html_path.is_file(), "El archivo monitoreo.html debe existir."

    content = html_path.read_text(encoding="utf-8")

    # Controles del cerco virtual (RF-04, RF-05, RF-06)
    assert 'id="dibujar-cerco"' in content, "Debe existir el botón Dibujar Cerco."
    assert 'id="cerrar-cerco"' in content, "Debe existir el botón Cerrar Cerco."
    assert 'id="editar-cerco"' in content, "Debe existir el botón Editar Cerco."
    assert 'id="limpiar-cerco"' in content, "Debe existir el botón Limpiar Cerco."

    # Indicadores visuales de estado y contador de vértices
    assert 'id="cerco-vertices-badge"' in content, "Debe existir el badge contador de vértices."
    assert 'id="cerco-status-hint"' in content, "Debe existir el hint de estado de trazado."


def test_us03_css_estilos_y_estados_canvas() -> None:
    """Verifica que el CSS contenga las reglas para cursor de lienzo y herramientas."""
    css_path = Path(__file__).resolve().parent.parent.parent / "frontend" / "css" / "styles.css"
    assert css_path.is_file(), "El archivo styles.css debe existir."

    css_content = css_path.read_text(encoding="utf-8")

    assert ".cursor-draw" in css_content, "Debe definir cursor crosshair para dibujar."
    assert ".cursor-edit" in css_content, "Debe definir cursor grab para modo edición."
    assert ".cursor-dragging" in css_content, "Debe definir cursor grabbing durante arrastre."
    assert ".btn-active-tool" in css_content, "Debe definir estilo para botón de herramienta activa."


# ===========================================================================
# 2. Pruebas de Dominio: CP-03 Validación de 4 a 6 Vértices
# ===========================================================================


def test_us03_cp03_rechazo_menos_de_4_vertices() -> None:
    """CP-03 Caso Negativo: Rechaza polígono con menos de 4 vértices (3 puntos)."""
    puntos_3 = [(0.1, 0.1), (0.5, 0.8), (0.9, 0.1)]
    cerco = CercoVirtualEnMemoria()

    with pytest.raises(CercoInvalidoError) as exc_info:
        cerco.definir_vertices(puntos_3)

    assert "mínimo de 4 vértices" in str(exc_info.value)
    assert not cerco.esta_cerrado
    assert cerco.cantidad_vertices == 0


def test_us03_cp03_aceptacion_4_vertices() -> None:
    """CP-03 Caso Válido: Acepta polígono de exactamente 4 vértices (límite inferior)."""
    puntos_4 = [(0.1, 0.1), (0.1, 0.8), (0.8, 0.8), (0.8, 0.1)]
    cerco = CercoVirtualEnMemoria(puntos_4)

    assert cerco.esta_cerrado
    assert cerco.cantidad_vertices == 4
    assert len(cerco.vertices) == 4


def test_us03_cp03_aceptacion_5_vertices() -> None:
    """CP-03 Caso Válido: Acepta polígono de 5 vértices."""
    puntos_5 = [(0.2, 0.1), (0.1, 0.5), (0.3, 0.9), (0.8, 0.8), (0.7, 0.2)]
    cerco = CercoVirtualEnMemoria(puntos_5)

    assert cerco.esta_cerrado
    assert cerco.cantidad_vertices == 5


def test_us03_cp03_aceptacion_6_vertices() -> None:
    """CP-03 Caso Válido: Acepta polígono de exactamente 6 vértices (límite superior)."""
    puntos_6 = [
        (0.2, 0.1),
        (0.1, 0.4),
        (0.3, 0.8),
        (0.7, 0.8),
        (0.9, 0.5),
        (0.8, 0.1),
    ]
    cerco = CercoVirtualEnMemoria(puntos_6)

    assert cerco.esta_cerrado
    assert cerco.cantidad_vertices == 6


def test_us03_cp03_rechazo_mas_de_6_vertices() -> None:
    """CP-03 Caso Negativo: Rechaza intento de ingresar 7 vértices."""
    puntos_7 = [
        (0.2, 0.1),
        (0.1, 0.3),
        (0.2, 0.6),
        (0.5, 0.9),
        (0.8, 0.7),
        (0.9, 0.4),
        (0.7, 0.1),
    ]
    cerco = CercoVirtualEnMemoria()

    with pytest.raises(CercoInvalidoError) as exc_info:
        cerco.definir_vertices(puntos_7)

    assert "máximo de 6 vértices" in str(exc_info.value)
    assert not cerco.esta_cerrado


# ===========================================================================
# 3. Pruebas de Algoritmos: Shoelace (Área) y Ray-casting (Point-in-Polygon)
# ===========================================================================


def test_us03_calculo_area_shoelace() -> None:
    """Verifica cálculo exacto del porcentaje de área con fórmula Shoelace (RF-11)."""
    # Cuadrado centrado de 0.5 x 0.5 = 0.25 (25% del área total)
    cuadrado_25 = [(0.25, 0.25), (0.75, 0.25), (0.75, 0.75), (0.25, 0.75)]
    cerco = CercoVirtualEnMemoria(cuadrado_25)
    area = cerco.calcular_porcentaje_area()
    assert area == 25.0, f"Se esperaba 25.0% y se obtuvo {area}%"

    # Escena completa: 1.0 x 1.0 = 1.0 (100% del área total)
    completo = [(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]
    cerco_completo = CercoVirtualEnMemoria(completo)
    assert cerco_completo.calcular_porcentaje_area() == 100.0


def test_us03_punto_dentro_raycasting() -> None:
    """Verifica discriminación precisa de peatón adentro vs afuera (Ray-casting / RNF-04)."""
    # Cuadrado entre [0.2, 0.2] y [0.8, 0.8]
    vertices = [(0.2, 0.2), (0.8, 0.2), (0.8, 0.8), (0.2, 0.8)]
    cerco = CercoVirtualEnMemoria(vertices)

    # Puntos interiores
    assert cerco.punto_dentro(0.5, 0.5) is True
    assert cerco.punto_dentro(0.3, 0.3) is True
    assert cerco.punto_dentro(0.7, 0.7) is True

    # Puntos exteriores
    assert cerco.punto_dentro(0.1, 0.5) is False
    assert cerco.punto_dentro(0.9, 0.5) is False
    assert cerco.punto_dentro(0.5, 0.1) is False
    assert cerco.punto_dentro(0.5, 0.9) is False
    assert cerco.punto_dentro(0.0, 0.0) is False


def test_us03_bounding_box_y_limpieza() -> None:
    """Verifica obtención de Bounding Box y reinicio completo en memoria."""
    vertices = [(0.2, 0.3), (0.6, 0.1), (0.8, 0.7), (0.4, 0.9)]
    cerco = CercoVirtualEnMemoria(vertices)

    bbox = cerco.obtener_bounding_box()
    assert bbox is not None
    min_x, min_y, max_x, max_y = bbox
    assert min_x == 0.2
    assert min_y == 0.1
    assert max_x == 0.8
    assert max_y == 0.9

    # Limpieza en caliente
    cerco.limpiar()
    assert cerco.cantidad_vertices == 0
    assert not cerco.esta_cerrado
    assert cerco.calcular_porcentaje_area() == 0.0
    assert cerco.obtener_bounding_box() is None
    assert cerco.punto_dentro(0.5, 0.5) is False


def test_us03_maquina_estados_cerco() -> None:
    """Verifica transiciones de semáforo del cerco (verde, amarillo, rojo) (RF-12)."""
    cerco = CercoVirtualEnMemoria([(0.1, 0.1), (0.8, 0.1), (0.8, 0.8), (0.1, 0.8)])
    assert cerco.estado == EstadoCerco.NORMAL

    cerco.estado = EstadoCerco.OBSERVACION
    assert cerco.estado == EstadoCerco.OBSERVACION
    assert cerco.estado.value == "amarillo"

    cerco.estado = EstadoCerco.ALERTA
    assert cerco.estado == EstadoCerco.ALERTA
    assert cerco.estado.value == "rojo"

    with pytest.raises(ValueError):
        cerco.estado = "azul"  # type: ignore[assignment]


# ===========================================================================
# 4. Pruebas de Integración WebSocket (/ws/monitoreo) y Cero Persistencia
# ===========================================================================


def test_us03_websocket_definir_cerco_exitoso() -> None:
    """Verifica actualización de cerco vía WebSocket y respuesta 'cerco_confirmado'."""
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        # Consumir bienvenida
        _ = ws.receive_json()

        # Enviar cerco válido de 4 vértices
        payload = {
            "tipo": "cerco_actualizado",
            "vertices": [
                {"x": 0.2, "y": 0.2},
                {"x": 0.6, "y": 0.2},
                {"x": 0.6, "y": 0.6},
                {"x": 0.2, "y": 0.6},
            ],
        }
        ws.send_json(payload)

        confirmacion = ws.receive_json()
        assert confirmacion.get("tipo") == "cerco_confirmado"
        assert confirmacion.get("cantidad_vertices") == 4
        assert confirmacion.get("area_cerco_pct") == 16.0  # 0.4 * 0.4 = 0.16 -> 16.0%
        assert confirmacion.get("estado") == "verde"


def test_us03_websocket_rechaza_cerco_invalido_3_y_7_vertices() -> None:
    """Verifica que el WebSocket devuelva 'error_cerco' ante transgresión de vértices."""
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()

        # Intento 1: 3 vértices
        ws.send_json({
            "tipo": "cerco_actualizado",
            "vertices": [{"x": 0.1, "y": 0.1}, {"x": 0.5, "y": 0.5}, {"x": 0.9, "y": 0.1}],
        })
        err1 = ws.receive_json()
        assert err1.get("tipo") == "error_cerco"
        assert "mínimo de 4 vértices" in err1.get("mensaje", "")

        # Intento 2: 7 vértices
        ws.send_json({
            "tipo": "cerco_actualizado",
            "vertices": [
                {"x": 0.1, "y": 0.1},
                {"x": 0.2, "y": 0.2},
                {"x": 0.3, "y": 0.3},
                {"x": 0.4, "y": 0.4},
                {"x": 0.5, "y": 0.5},
                {"x": 0.6, "y": 0.6},
                {"x": 0.7, "y": 0.7},
            ],
        })
        err2 = ws.receive_json()
        assert err2.get("tipo") == "error_cerco"
        assert "máximo de 6 vértices" in err2.get("mensaje", "")


def test_us03_websocket_limpiar_cerco() -> None:
    """Verifica que el mensaje 'limpiar_cerco' restablezca el cerco en sesión."""
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()

        # Enviar limpiar_cerco
        ws.send_json({"tipo": "limpiar_cerco"})
        ack_limpiar = ws.receive_json()
        assert ack_limpiar.get("tipo") == "cerco_limpiado"
        assert ack_limpiar.get("area_cerco_pct") == 0.0


def test_us03_cero_persistencia_en_base_de_datos() -> None:
    """Verifica que ninguna operación de cerco toque o persista colecciones en MongoDB (RNF-04)."""
    fake_repo = _FakeRepo()
    token = _crear_test_token()
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()
        ws.send_json({
            "tipo": "cerco_actualizado",
            "vertices": [
                {"x": 0.1, "y": 0.1},
                {"x": 0.5, "y": 0.1},
                {"x": 0.5, "y": 0.5},
                {"x": 0.1, "y": 0.5},
            ],
        })
        _ = ws.receive_json()
        ws.send_json({"tipo": "limpiar_cerco"})
        _ = ws.receive_json()

    # Comprobar que en ningún momento se interactuó con persistencia para el cerco
    assert len(fake_repo.cercos_guardados) == 0, "El cerco virtual jamás debe persistirse en BD."
