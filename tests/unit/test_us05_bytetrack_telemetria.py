"""Pruebas unitarias e integrales para la Historia de Usuario 5 (US-05 / RF-08 / RF-11 / CP-04).

Verifica sobre CPU y memoria RAM (RNF-01) conforme a Requisitos_Sistema_VI V 1.2:
1. Modelo inmutable de las 8 métricas computacionales (`MetricasOperativas`).
2. `MonitorTelemetriaProceso` (FPS EMA, CPU, RAM, % GPU opcional en CPU-only y KB/s de payload).
3. `RastreadorByteTrack`: persistencia de `track_id`, cola de `trayectoria`, recuperación en
   2.ª pasada con baja confianza y supervivencia ante oclusiones breves (`track_buffer`).
4. Invariancia del `track_id` al reajustar en caliente los vértices del cerco virtual (RF-06).
5. Integración E2E en `/ws/monitoreo` (CP-04) y verificación de las 8 tarjetas en `monitoreo.html`.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import struct
from typing import Any, Optional, Sequence
import uuid
import zlib

from fastapi.testclient import TestClient
import jwt

from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.config import Settings
from backend.app.core.telemetry import MonitorTelemetriaProceso
from backend.app.domain.cerco_virtual import CercoVirtualEnMemoria
from backend.app.domain.metricas import MetricasOperativas
from backend.app.domain.ports import CajaDeteccionCruda, DeteccionPeaton
from backend.app.main import create_app
from backend.app.vision.estrategias_roi import EstrategiaCercoVirtual
from backend.app.vision.tracker_bytetrack import RastreadorByteTrack
from backend.app.vision.yolo_detector import DetectorYOLOCPU, ImagenMemoria

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"
_CLAVES_8_METRICAS = (
    "fps",
    "inferencia_ms",
    "area_cerco_pct",
    "cpu_pct",
    "ram_mb",
    "gpu_pct",
    "ancho_banda_kbs",
    "peatones",
    "alertas",
)


class _FakeRepo:
    """Repositorio ligero en memoria para pruebas WebSocket de US-05."""

    def __init__(self, active_token: Optional[str] = None) -> None:
        self.active_token = active_token or str(uuid.uuid4())
        self.users: dict[str, dict[str, Any]] = {
            "vi": {
                "usuario": "vi",
                "correo": "operador@espe.edu.ec",
                "token_sesion_unica": self.active_token,
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

    def asegurarIndicesUsuarios(self) -> None:
        pass

    def validarCredencialesUnicas(self, usuario: str) -> Optional[dict[str, Any]]:
        user = self.users.get(usuario)
        return dict(user) if user else None


def _crear_token_prueba(username: str = "vi") -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "usuario": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=2)).timestamp()),
    }
    return jwt.encode(payload, _TEST_JWT_SECRET, algorithm="HS256")


def _generar_png_b64_minimo(ancho: int = 640, alto: int = 480) -> str:
    """Construye un PNG válido mínimo en memoria para ejercitar el decodificador WS."""

    def _chunk(tag: bytes, datos: bytes) -> bytes:
        crc = zlib.crc32(tag + datos) & 0xFFFFFFFF
        return struct.pack(">I", len(datos)) + tag + datos + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", ancho, alto, 8, 2, 0, 0, 0)
    fila_cruda = b"\x00" + (b"\x20\x40\x60" * ancho)
    idat = zlib.compress(fila_cruda * min(alto, 2))
    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")
    return base64.b64encode(png).decode("ascii")


def _crear_cliente_ws(
    fake_repo: _FakeRepo, detector: DetectorYOLOCPU
) -> TestClient:
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
    app = create_app(settings=settings, repositorio=fake_repo, gestor=gestor)  # type: ignore[arg-type]
    app.state.detector_yolo = detector
    return TestClient(app)


# ===========================================================================
# 1. Pruebas de las 8 Métricas Computacionales y Telemetría (RF-11 / V 1.2)
# ===========================================================================


def test_us05_metricas_operativas_serializa_las_8_metricas_v12() -> None:
    """Verifica el contrato completo y acotamiento de las 8 métricas computacionales."""
    m = MetricasOperativas(
        fps=14.86,
        inferencia_ms=28.439,
        area_cerco_pct=32.556,
        cpu_pct=41.24,
        ram_mb=312.68,
        gpu_pct=0.0,
        ancho_banda_kbs=184.72,
        peatones=2,
        alertas=0,
    )
    serializado = m.to_dict()
    assert all(k in serializado for k in _CLAVES_8_METRICAS)
    assert serializado["fps"] == 14.9
    assert serializado["inferencia_ms"] == 28.44
    assert serializado["area_cerco_pct"] == 32.56
    assert serializado["gpu_pct"] == 0.0
    assert serializado["ancho_banda_kbs"] == 184.7
    assert serializado["peatones"] == 2
    assert serializado["alertas"] == 0


def test_us05_monitor_telemetria_calcula_fps_ancho_banda_cpu_ram_y_gpu() -> None:
    """Valida ventana deslizante de KB/s, FPS suavizado, psutil y sonda GPU opcional."""
    monitor = MonitorTelemetriaProceso(ventana_banda_seg=2.0, lector_gpu=lambda: 0.0)

    # Simular 3 fotogramas espaciados por 0.10 s (~10 FPS) y 20 KB de payload en 1.0 s
    monitor.registrar_fotograma(timestamp=10.0)
    fps_2 = monitor.registrar_fotograma(timestamp=10.10)
    fps_3 = monitor.registrar_fotograma(timestamp=10.20)
    assert 9.5 <= fps_2 <= 10.5
    assert 9.5 <= fps_3 <= 10.5

    monitor.registrar_bytes_payload(10 * 1024, timestamp=10.0)
    kbs = monitor.registrar_bytes_payload(10 * 1024, timestamp=11.0)
    # 20 KB acumulados a lo largo de 1.0 segundo -> 20.0 KB/s
    assert 19.5 <= kbs <= 20.5

    corte = monitor.construir_metricas(
        inferencia_ms=19.5, area_cerco_pct=25.0, peatones=1, alertas=0
    ).to_dict()
    assert corte["cpu_pct"] >= 0.0
    assert corte["ram_mb"] > 0.0
    assert corte["gpu_pct"] == 0.0

    monitor.reiniciar()
    assert monitor.calcular_ancho_banda_kbs(timestamp=12.0) == 0.0


# ===========================================================================
# 2. Pruebas Unitarias de ByteTrack en CPU (RF-08 / RNF-01)
# ===========================================================================


def test_us05_bytetrack_conserva_ids_y_acumula_trayectoria_dos_peatones() -> None:
    """Verifica IDs distintos sin intercambio (`ID Switch = 0`) y límite de estela."""
    tracker = RastreadorByteTrack(max_puntos_trayectoria=4)

    for paso in range(6):
        dx = paso * 0.02
        p1 = DeteccionPeaton(
            x1=0.20 + dx, y1=0.30, x2=0.28 + dx, y2=0.55, confianza=0.88
        )
        p2 = DeteccionPeaton(
            x1=0.70 - dx, y1=0.35, x2=0.78 - dx, y2=0.60, confianza=0.82
        )
        salida = tracker.actualizar([p1, p2])
        assert len(salida) == 2
        assert salida[0].track_id == 1
        assert salida[1].track_id == 2

    # La cola circular debe truncarse exactamente en max_puntos_trayectoria = 4
    assert len(salida[0].trayectoria) == 4
    assert salida[0].trayectoria[-1] == salida[0].punto_pies


def test_us05_bytetrack_recupera_segunda_pasada_baja_confianza_y_oclusion() -> None:
    """Comprueba asociación en 2.ª pasada (conf=0.20) y retención durante oclusión breve."""
    tracker = RastreadorByteTrack(conf_alta=0.35, conf_baja=0.15, max_frames_perdidos=5)

    # Cuadro 1: aparición con alta confianza -> ID #1
    s1 = tracker.actualizar(
        [DeteccionPeaton(x1=0.40, y1=0.30, x2=0.48, y2=0.58, confianza=0.85)]
    )
    assert len(s1) == 1 and s1[0].track_id == 1

    # Cuadro 2: desenfoque / sombra reduce confianza a 0.21 -> recuperado en 2.ª pasada!
    s2 = tracker.actualizar(
        [DeteccionPeaton(x1=0.41, y1=0.30, x2=0.49, y2=0.58, confianza=0.21)]
    )
    assert len(s2) == 1
    assert s2[0].track_id == 1
    assert len(s2[0].trayectoria) == 2

    # Cuadros 3 y 4: oclusión completa detrás de obstáculo (0 detecciones)
    assert tracker.actualizar([]) == ()
    assert tracker.actualizar([]) == ()
    assert tracker.pistas_en_memoria == 1

    # Cuadro 5: reaparece cerca de la trayectoria predicha -> conserva ID #1!
    s5 = tracker.actualizar(
        [DeteccionPeaton(x1=0.43, y1=0.30, x2=0.51, y2=0.58, confianza=0.80)]
    )
    assert len(s5) == 1
    assert s5[0].track_id == 1
    assert len(s5[0].trayectoria) == 3


def test_us05_invariancia_track_id_al_editar_vertices_cerco_en_caliente() -> None:
    """Verifica que arrastrar los vértices del cerco (RF-06) no rompa el track_id global."""
    cerco = CercoVirtualEnMemoria()
    cerco.definir_vertices(
        [{"x": 0.20, "y": 0.20}, {"x": 0.80, "y": 0.20}, {"x": 0.80, "y": 0.80}, {"x": 0.20, "y": 0.80}]
    )
    estrategia = EstrategiaCercoVirtual(padding_pct=0.10, conf_min=0.35)
    tracker = RastreadorByteTrack()

    # El peatón permanece en la coordenada global fija [280..340, 180..320] de un frame 640x480
    def _predictor_global_fijo(subimg: ImagenMemoria, **_kw: Any) -> Sequence[CajaDeteccionCruda]:
        ox, oy = subimg.offset_x, subimg.offset_y
        return [
            CajaDeteccionCruda(
                x1=280.0 - ox,
                y1=180.0 - oy,
                x2=340.0 - ox,
                y2=320.0 - oy,
                confianza=0.90,
                clase_id=0,
            )
        ]

    detector = DetectorYOLOCPU(predictor_fn=_predictor_global_fijo)
    frame = ImagenMemoria(ancho=640, alto=480)

    r1 = estrategia.procesar(frame, cerco, detector, rastreador=tracker)
    assert len(r1.detecciones) == 1
    assert r1.detecciones[0].track_id == 1

    # El operador arrastra en vivo las esquinas izquierdas del cerco cambiando el offset del ROI
    cerco.definir_vertices(
        [{"x": 0.32, "y": 0.25}, {"x": 0.85, "y": 0.25}, {"x": 0.85, "y": 0.85}, {"x": 0.32, "y": 0.85}]
    )
    r2 = estrategia.procesar(frame, cerco, detector, rastreador=tracker)
    assert len(r2.detecciones) == 1
    assert r2.detecciones[0].track_id == 1
    assert len(r2.detecciones[0].trayectoria) == 2


# ===========================================================================
# 3. Integración WebSocket CP-04 y Verificación de Interfaz Web
# ===========================================================================


def test_us05_websocket_cp04_emite_track_id_trayectoria_y_8_metricas() -> None:
    """Valida extremo a extremo CP-04 sobre /ws/monitoreo y reinicio al limpiar cerco."""
    paso_ws = {"n": 0}

    def _predictor_animado(subimg: Any, **_kw: Any) -> Sequence[CajaDeteccionCruda]:
        h, w = subimg.shape[0], subimg.shape[1]
        desplazamiento = paso_ws["n"] * 6.0
        paso_ws["n"] += 1
        cx, cy = (w * 0.5) + desplazamiento, h * 0.5
        return [
            CajaDeteccionCruda(
                x1=cx - 20.0,
                y1=cy - 45.0,
                x2=cx + 20.0,
                y2=cy + 45.0,
                confianza=0.89,
                clase_id=0,
            )
        ]

    detector = DetectorYOLOCPU(predictor_fn=_predictor_animado)
    token = _crear_token_prueba()
    fake_repo = _FakeRepo(active_token=token)
    client = _crear_cliente_ws(fake_repo, detector)
    frame_b64 = _generar_png_b64_minimo(640, 480)

    with client.websocket_connect(f"/ws/monitoreo?token={token}") as ws:
        bienvenida = ws.receive_json()
        assert bienvenida["tipo"] == "conexion_establecida"
        assert all(k in bienvenida["telemetria_inicial"] for k in _CLAVES_8_METRICAS)

        # Trazar cerco cuadrado del 36% central (0.6 * 0.6)
        ws.send_json(
            {
                "tipo": "cerco_actualizado",
                "vertices": [
                    {"x": 0.2, "y": 0.2},
                    {"x": 0.8, "y": 0.2},
                    {"x": 0.8, "y": 0.8},
                    {"x": 0.2, "y": 0.8},
                ],
            }
        )
        assert ws.receive_json()["tipo"] == "cerco_confirmado"

        # Enviar 3 cuadros consecutivos
        ultimo_msg: dict[str, Any] = {}
        for _ in range(3):
            ws.send_json(
                {"tipo": "procesar_frame", "frame_b64": frame_b64, "ancho": 640, "alto": 480}
            )
            ultimo_msg = ws.receive_json()

        assert ultimo_msg["tipo"] == "resultado_deteccion"
        assert ultimo_msg["peatones_detectados"] == 1
        det = ultimo_msg["detecciones"][0]
        assert det["track_id"] == 1
        assert len(det["trayectoria"]) == 3

        metricas = ultimo_msg["metricas"]
        assert all(k in metricas for k in _CLAVES_8_METRICAS)
        assert metricas["area_cerco_pct"] == 36.0
        assert metricas["ancho_banda_kbs"] > 0.0
        assert metricas["peatones"] == 1

        # Limpiar cerco debe reiniciar también el rastreador ByteTrack de la sesión
        ws.send_json({"tipo": "limpiar_cerco"})
        assert ws.receive_json()["tipo"] == "cerco_limpiado"


def test_us05_frontend_panel_8_metricas_y_renderizado_bytetrack() -> None:
    """Verifica las 8 tarjetas de métricas en monitoreo.html y el trazo de IDs/rutas en JS."""
    raiz = Path(__file__).resolve().parent.parent.parent
    html = (raiz / "frontend" / "monitoreo.html").read_text(encoding="utf-8")
    canvas_js = (raiz / "frontend" / "js" / "components" / "cerco_canvas.js").read_text(
        encoding="utf-8"
    )
    mon_js = (raiz / "frontend" / "js" / "monitoreo.js").read_text(encoding="utf-8")

    for id_esperado in (
        'id="metric-fps"',
        'id="metric-ms"',
        'id="metric-area"',
        'id="metric-cpu"',
        'id="metric-ram"',
        'id="metric-gpu"',
        'id="metric-bw"',
        'id="metric-conteo"',
    ):
        assert id_esperado in html, f"Falta celda de métrica {id_esperado} en monitoreo.html"

    assert "Ancho de Banda" in html and "KB/s" in html
    assert "GPU" in html
    assert "det.trayectoria" in canvas_js
    assert "ID #" in canvas_js
    assert "ancho_banda_kbs" in mon_js and "gpu_pct" in mon_js
