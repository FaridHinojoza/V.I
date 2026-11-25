"""Pruebas unitarias e integrales para la Historia de Usuario 4 (US-04 / RF-07 / RNF-01 / RNF-02 / CP-04).

Verifica la ejecución de YOLO sobre el área del cerco virtual operando 100 % en CPU y memoria RAM:
- Ejecución exclusiva en CPU (`device='cpu'`) y filtrado de clase 0 (persona) (RNF-01, RF-07).
- Margen de expansión asimétrico (padding RNF-02) que conserva la figura completa del peatón.
- Escalado dinámico de resolución `imgsz` (múltiplo de 32) proporcional al recorte en CPU.
- Filtrado geométrico exacto Point-in-Polygon (Ray-casting): solo personas dentro del cerco.
- Procesamiento en vivo por canal WebSocket `/ws/monitoreo` (`procesar_frame` -> `resultado_deteccion`).
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import struct
from typing import Any, List, Optional, Sequence
import uuid

from fastapi.testclient import TestClient
import jwt
import pytest

from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.config import Settings
from backend.app.domain.cerco_virtual import CercoVirtualEnMemoria
from backend.app.domain.ports import CajaDeteccionCruda, DeteccionPeaton
from backend.app.main import create_app
from backend.app.vision.estrategias_roi import (
    EstrategiaCercoVirtual,
    EstrategiaEscenaCompleta,
    calcular_imgsz_dinamico,
)
from backend.app.vision.yolo_detector import (
    DetectorYOLOCPU,
    FrameInvalidoError,
    ImagenMemoria,
    decodificar_frame_base64,
)

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"


class _FakeUpdateResult:
    def __init__(self, matched_count: int, modified_count: int) -> None:
        self.matched_count = matched_count
        self.modified_count = modified_count


class _FakeRepo:
    """Repositorio simulado en memoria para pruebas de sesión única y cero persistencia."""

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
    session_id: str = "session-test-us04",
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


def _generar_png_base64_sintetico(ancho: int = 640, alto: int = 480) -> str:
    """Construye una cabecera PNG binaria válida con dimensiones exactas codificada en Base64."""
    firma_png = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", ancho, alto, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", 13) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
    raw = firma_png + ihdr_chunk
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def _build_test_client(
    fake_repo: _FakeRepo,
    detector: Optional[DetectorYOLOCPU] = None,
) -> tuple[TestClient, GestorSesionUnica, Settings]:
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
        yolo_model_path="models/yolo11n.pt",
        yolo_conf_threshold=0.35,
        yolo_imgsz_max=640,
        roi_padding_pct=0.10,
    )
    gestor = GestorSesionUnica(repositorio=fake_repo, settings=settings)  # type: ignore[arg-type]
    fastapi_app = create_app(settings=settings, repositorio=fake_repo, gestor=gestor)  # type: ignore[arg-type]
    if detector is not None:
        fastapi_app.state.detector_yolo = detector
    client = TestClient(fastapi_app)
    return client, gestor, settings


# ===========================================================================
# 1. Pruebas de Ejecución 100 % en CPU y Filtrado Clase Persona (RNF-01 / RF-07)
# ===========================================================================


def test_us04_rnf01_detector_opera_exclusivamente_en_cpu_y_clase_persona() -> None:
    """Verifica que DetectorYOLOCPU fuerce device='cpu' y classes=[0] descartando otras clases."""
    llamados: List[dict[str, Any]] = []

    def _fake_predictor(imagen: Any, **kwargs: Any) -> Sequence[CajaDeteccionCruda]:
        llamados.append(kwargs)
        return [
            # Persona válida (clase 0, confianza 0.88)
            CajaDeteccionCruda(x1=50.0, y1=40.0, x2=110.0, y2=180.0, confianza=0.88, clase_id=0),
            # Automóvil (clase 2 -> debe descartarse)
            CajaDeteccionCruda(x1=10.0, y1=10.0, x2=200.0, y2=150.0, confianza=0.95, clase_id=2),
            # Mochila (clase 24 -> debe descartarse)
            CajaDeteccionCruda(x1=60.0, y1=80.0, x2=90.0, y2=120.0, confianza=0.91, clase_id=24),
            # Persona con baja confianza (0.18 < 0.35 -> debe descartarse)
            CajaDeteccionCruda(x1=120.0, y1=30.0, x2=160.0, y2=140.0, confianza=0.18, clase_id=0),
        ]

    detector = DetectorYOLOCPU(predictor_fn=_fake_predictor)
    assert detector.dispositivo == "cpu"

    frame = ImagenMemoria(ancho=320, alto=240)
    resultados = detector.detectar_personas(frame, imgsz=320, conf_min=0.35)

    assert len(llamados) == 1
    assert llamados[0]["device"] == "cpu"
    assert llamados[0]["classes"] == [0]
    assert llamados[0]["imgsz"] == 320
    assert detector.ultimo_llamado_kwargs["device"] == "cpu"

    assert len(resultados) == 1
    assert resultados[0].clase_id == 0
    assert resultados[0].confianza == 0.88


# ===========================================================================
# 2. Pruebas de Aislamiento Espacial, Padding RNF-02 e imgsz Dinámico (RF-07)
# ===========================================================================


def test_us04_rnf02_padding_asimetrico_conserva_figura_completa_peaton() -> None:
    """Verifica que el recorte expanda el bounding box del polígono para no amputar personas (RNF-02)."""
    # Cerco cuadrado en el centro: X en [0.30, 0.70], Y en [0.40, 0.80] sobre frame 1000x1000
    cerco = CercoVirtualEnMemoria([(0.30, 0.40), (0.70, 0.40), (0.70, 0.80), (0.30, 0.80)])
    estrategia = EstrategiaCercoVirtual(padding_pct=0.10, imgsz_max=640, conf_min=0.35)

    recorte = estrategia.calcular_recorte_roi(cerco, ancho_frame=1000, alto_frame=1000)

    # Sin padding, el bounding box sería x1=300, y1=400, x2=700, y2=800.
    # Con padding RNF-02 (pad_x=0.10, pad_y_superior=0.18, pad_y_inferior=0.05):
    assert recorte.x1_px == 200  # (0.30 - 0.10) * 1000
    assert recorte.y1_px == 220  # (0.40 - 0.18) * 1000 -> margen superior ampliado para cabeza/torso
    assert recorte.x2_px == 800  # (0.70 + 0.10) * 1000
    assert recorte.y2_px == 850  # (0.80 + 0.05) * 1000
    assert recorte.ancho_recorte == 600
    assert recorte.alto_recorte == 630


def test_us04_rf07_imgsz_dinamico_multiplo_32_optimiza_cpu() -> None:
    """Verifica que imgsz se ajuste a múltiplos de 32 reduciendo carga en CPU para cercos compactos."""
    # Un recorte de 180x150 px debe redondearse al múltiplo de 32 inmediatamente superior: 192
    imgsz_pequeno = calcular_imgsz_dinamico(180, 150, imgsz_min=160, imgsz_max=640)
    assert imgsz_pequeno == 192
    assert imgsz_pequeno % 32 == 0
    assert imgsz_pequeno < 640

    # Un recorte muy pequeño (80x80) respeta el piso mínimo de 160 px para no perder rasgos
    assert calcular_imgsz_dinamico(80, 80, imgsz_min=160, imgsz_max=640) == 160

    # Un recorte grande (720x540) se acota al techo máximo de 640 px
    assert calcular_imgsz_dinamico(720, 540, imgsz_min=160, imgsz_max=640) == 640


def test_us04_criterio_aceptacion_detecta_exclusivamente_personas_dentro_del_cerco() -> None:
    """Criterio de Aceptación US-04: Identifica exclusivamente personas dentro de la región delimitada."""
    # Frame de 1000x1000 px; Cerco de 4 vértices entre [0.30, 0.30] y [0.70, 0.70] (Área = 16%)
    cerco = CercoVirtualEnMemoria([(0.30, 0.30), (0.70, 0.30), (0.70, 0.70), (0.30, 0.70)])
    estrategia = EstrategiaCercoVirtual(padding_pct=0.10, imgsz_max=640, conf_min=0.35)

    # Con padding_pct=0.10:
    # x1_px = 200 (0.20), y1_px = 120 (0.12), x2_px = 800 (0.80), y2_px = 750 (0.75)
    def _predictor_dos_personas(imagen: Any, **kwargs: Any) -> Sequence[CajaDeteccionCruda]:
        return [
            # Peatón 1: En coordenadas locales del recorte (x1=250..350, y1=180..430)
            # Global: x1=450..550 (0.45..0.55), y1=300..550 (0.30..0.55)
            # Punto pies = (0.50, 0.55) -> DENTRO del cerco [0.30..0.70]
            CajaDeteccionCruda(x1=250.0, y1=180.0, x2=350.0, y2=430.0, confianza=0.92, clase_id=0),
            # Peatón 2: En el margen de padding pero FUERA del polígono del cerco
            # Local: x1=10..60, y1=20..120 -> Global: x1=210..260 (0.21..0.26), y1=140..240 (0.14..0.24)
            # Punto pies = (0.235, 0.24) y centroide = (0.235, 0.19) -> FUERA del cerco [0.30..0.70]
            CajaDeteccionCruda(x1=10.0, y1=20.0, x2=60.0, y2=120.0, confianza=0.89, clase_id=0),
        ]

    detector = DetectorYOLOCPU(predictor_fn=_predictor_dos_personas)
    frame = ImagenMemoria(ancho=1000, alto=1000)

    resultado = estrategia.procesar(imagen=frame, cerco=cerco, detector=detector)

    assert resultado.cerco_activo is True
    assert resultado.dispositivo == "cpu"
    assert resultado.area_cerco_pct == 16.0
    assert resultado.peatones_detectados == 1, "Solo debe conservar al peatón dentro del polígono."

    peaton: DeteccionPeaton = resultado.detecciones[0]
    assert peaton.clase_id == 0
    assert peaton.confianza == 0.92
    assert peaton.x1 == pytest.approx(0.45, abs=1e-4)
    assert peaton.x2 == pytest.approx(0.55, abs=1e-4)
    assert peaton.y2 == pytest.approx(0.55, abs=1e-4)
    assert cerco.punto_dentro(*peaton.punto_pies) is True


def test_us04_estrategia_escena_completa_referencia() -> None:
    """Verifica que EstrategiaEscenaCompleta opere en CPU con 100 % del área."""
    detector = DetectorYOLOCPU(
        predictor_fn=lambda img, **kw: [
            CajaDeteccionCruda(x1=100.0, y1=100.0, x2=200.0, y2=300.0, confianza=0.81, clase_id=0)
        ]
    )
    estrategia = EstrategiaEscenaCompleta(imgsz=640, conf_min=0.35)
    frame = ImagenMemoria(ancho=640, alto=480)

    res = estrategia.procesar(imagen=frame, detector=detector)
    assert res.area_cerco_pct == 100.0
    assert res.dispositivo == "cpu"
    assert res.imgsz_usado == 640
    assert res.peatones_detectados == 1


# ===========================================================================
# 3. Pruebas de Decodificación Base64 en Memoria RAM
# ===========================================================================


def test_us04_decodificador_base64_png_y_rechazo_corruptos() -> None:
    """Verifica decodificación en memoria RAM y rechazo de tramas inválidas."""
    b64_valido = _generar_png_base64_sintetico(ancho=800, alto=600)
    img = decodificar_frame_base64(b64_valido)
    assert hasattr(img, "shape")
    assert img.shape[0] == 600  # alto
    assert img.shape[1] == 800  # ancho

    with pytest.raises(FrameInvalidoError):
        decodificar_frame_base64("")

    with pytest.raises(FrameInvalidoError):
        decodificar_frame_base64("data:image/jpeg;base64,%%%NO_ES_BASE64%%%")


# ===========================================================================
# 4. Pruebas de Integración WebSocket (/ws/monitoreo) para US-04
# ===========================================================================


def test_us04_websocket_procesar_frame_sin_cerco_no_ejecuta_yolo() -> None:
    """Verifica que enviar 'procesar_frame' sin cerco activo no invoque inferencia YOLO."""
    invocaciones = 0

    def _predictor_espia(imagen: Any, **kwargs: Any) -> Sequence[CajaDeteccionCruda]:
        nonlocal invocaciones
        invocaciones += 1
        return []

    detector = DetectorYOLOCPU(predictor_fn=_predictor_espia)
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo, detector=detector)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()  # conexion_establecida

        ws.send_json({
            "tipo": "procesar_frame",
            "frame_b64": _generar_png_base64_sintetico(640, 480),
            "ancho": 640,
            "alto": 480,
        })
        respuesta = ws.receive_json()

        assert respuesta["tipo"] == "resultado_deteccion"
        assert respuesta["cerco_activo"] is False
        assert respuesta["peatones_detectados"] == 0
        assert respuesta["detecciones"] == []
        assert respuesta["dispositivo"] == "cpu"
        assert invocaciones == 0


def test_us04_websocket_procesar_frame_con_cerco_detecta_peatones_en_cpu() -> None:
    """Verifica el flujo completo en /ws/monitoreo: trazar cerco 4-6 vértices y detectar en CPU."""

    def _predictor_ws(imagen: Any, **kwargs: Any) -> Sequence[CajaDeteccionCruda]:
        # El recorte ROI tiene dimensiones según el cerco [0.25..0.75] en 640x480:
        # Devolver una persona en el centro del recorte y otra fuera del polígono
        alto_roi, ancho_roi = imagen.shape[0], imagen.shape[1]
        cx = ancho_roi / 2.0
        cy = alto_roi / 2.0
        return [
            # Peatón centrado dentro del polígono
            CajaDeteccionCruda(
                x1=cx - 25.0,
                y1=cy - 60.0,
                x2=cx + 25.0,
                y2=cy + 40.0,
                confianza=0.91,
                clase_id=0,
            ),
            # Peatón en la esquina superior izquierda del padding (fuera del polígono)
            CajaDeteccionCruda(
                x1=1.0,
                y1=1.0,
                x2=12.0,
                y2=20.0,
                confianza=0.84,
                clase_id=0,
            ),
        ]

    detector = DetectorYOLOCPU(predictor_fn=_predictor_ws)
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo, detector=detector)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()  # conexion_establecida

        # 1. Definir cerco de 4 vértices cubriendo el 25% central del fotograma
        ws.send_json({
            "tipo": "cerco_actualizado",
            "vertices": [
                {"x": 0.25, "y": 0.25},
                {"x": 0.75, "y": 0.25},
                {"x": 0.75, "y": 0.75},
                {"x": 0.25, "y": 0.75},
            ],
        })
        confirmacion = ws.receive_json()
        assert confirmacion["tipo"] == "cerco_confirmado"
        assert confirmacion["area_cerco_pct"] == 25.0

        # 2. Enviar fotograma para detección con YOLO en CPU
        ws.send_json({
            "tipo": "procesar_frame",
            "frame_b64": _generar_png_base64_sintetico(640, 480),
            "ancho": 640,
            "alto": 480,
        })
        det_msg = ws.receive_json()

        assert det_msg["tipo"] == "resultado_deteccion"
        assert det_msg["cerco_activo"] is True
        assert det_msg["dispositivo"] == "cpu"
        assert det_msg["area_cerco_pct"] == 25.0
        assert det_msg["inferencia_ms"] >= 0.0
        assert det_msg["peatones_detectados"] == 1
        assert len(det_msg["detecciones"]) == 1

        caja = det_msg["detecciones"][0]
        assert caja["clase_id"] == 0
        assert caja["confianza"] == 0.91
        assert 0.25 <= caja["punto_pies"]["x"] <= 0.75
        assert 0.25 <= caja["punto_pies"]["y"] <= 0.75


def test_us04_websocket_frame_corrupto_devuelve_error_procesamiento_sin_cerrar_ws() -> None:
    """Verifica resiliencia del canal WebSocket ante un fotograma Base64 malformado."""
    detector = DetectorYOLOCPU(predictor_fn=lambda img, **kw: [])
    token = _crear_test_token()
    fake_repo = _FakeRepo(active_session_id=token)
    fake_repo.users["vi"]["token_sesion_unica"] = token
    client, _, _ = _build_test_client(fake_repo, detector=detector)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        _ = ws.receive_json()

        ws.send_json({
            "tipo": "cerco_actualizado",
            "vertices": [
                {"x": 0.2, "y": 0.2},
                {"x": 0.8, "y": 0.2},
                {"x": 0.8, "y": 0.8},
                {"x": 0.2, "y": 0.8},
            ],
        })
        _ = ws.receive_json()

        # Enviar frame corrupto
        ws.send_json({"tipo": "procesar_frame", "frame_b64": "!!no_base64!!"})
        err_msg = ws.receive_json()
        assert err_msg["tipo"] == "error_procesamiento"

        # El canal sigue vivo y responde ping/pong
        ws.send_json({"tipo": "ping"})
        pong = ws.receive_json()
        assert pong["tipo"] == "pong"


def test_us04_frontend_monitoreo_js_integra_envio_y_renderizado_detecciones() -> None:
    """Verifica que monitoreo.js implemente el envío de 'procesar_frame' y el dibujo de cajas."""
    js_path = Path(__file__).resolve().parent.parent.parent / "frontend" / "js" / "monitoreo.js"
    assert js_path.is_file(), "El archivo frontend/js/monitoreo.js debe existir."

    contenido = js_path.read_text(encoding="utf-8")
    assert '"procesar_frame"' in contenido
    assert '"resultado_deteccion"' in contenido
    assert "deteccionesActivas" in contenido
    assert "esperandoDeteccion" in contenido
    assert "capturarYEnviarFrameCerco" in contenido
