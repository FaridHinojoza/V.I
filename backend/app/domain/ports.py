"""Puertos (Protocol) y objetos de valor de dominio para detección y seguimiento en CPU y RAM.

Define las estructuras inmutables para el intercambio entre el adaptador de visión
(Ultralytics YOLO en CPU), el rastreador multi-objeto (ByteTrack) y las estrategias
de aislamiento espacial del cerco virtual (US-04 / US-05 / RF-07 / RF-08 / RNF-01 / RNF-02).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol, Sequence, Tuple, runtime_checkable


@dataclass(frozen=True)
class CajaDeteccionCruda:
    """Caja delimitadora en coordenadas de píxeles locales del tensor o recorte analizado.

    Attributes:
        x1: Coordenada horizontal izquierda en píxeles locales.
        y1: Coordenada vertical superior en píxeles locales.
        x2: Coordenada horizontal derecha en píxeles locales.
        y2: Coordenada vertical inferior en píxeles locales.
        confianza: Puntaje de confianza del detector en el rango [0.0, 1.0].
        clase_id: Identificador numérico de clase COCO (0 corresponde a persona).
    """

    x1: float
    y1: float
    x2: float
    y2: float
    confianza: float
    clase_id: int = 0


@dataclass(frozen=True)
class DeteccionPeaton:
    """Representa una persona (class 0) detectada y opcionalmente rastreada en el cerco.

    Todas las coordenadas se almacenan normalizadas en el rango [0.0, 1.0] respecto al
    ancho y alto totales del fotograma original, desacoplando la geometría de dominio
    de la resolución de la cámara o del lienzo HTML5 Canvas.

    Attributes:
        x1: Límite izquierdo normalizado [0.0, 1.0].
        y1: Límite superior normalizado [0.0, 1.0].
        x2: Límite derecho normalizado [0.0, 1.0].
        y2: Límite inferior normalizado [0.0, 1.0].
        confianza: Probabilidad estimada por YOLO [0.0, 1.0].
        clase_id: Clase detectada (invariante = 0 para peatones).
        track_id: Identificador continuo asignado por ByteTrack en la sesión (US-05 / RF-08).
        trayectoria: Secuencia cronológica de puntos (x, y) normalizados del recorrido.
    """

    x1: float
    y1: float
    x2: float
    y2: float
    confianza: float
    clase_id: int = 0
    track_id: Optional[int] = None
    trayectoria: Tuple[Tuple[float, float], ...] = ()

    @property
    def punto_pies(self) -> Tuple[float, float]:
        """Calcula el punto de apoyo inferior central del peatón sobre el plano del suelo.

        Por qué: En cámaras de videovigilancia con perspectiva oblicua, la posición real
        de una persona respecto a un polígono trazado sobre el piso está determinada por
        la base inferior de su caja delimitadora ((x1 + x2) / 2, y2).

        Returns:
            Tupla (px, py) normalizada en [0.0, 1.0].
        """
        return (round((self.x1 + self.x2) / 2.0, 6), round(self.y2, 6))

    @property
    def centroide(self) -> Tuple[float, float]:
        """Calcula el centro geométrico de la caja delimitadora de la persona.

        Returns:
            Tupla (cx, cy) normalizada en [0.0, 1.0].
        """
        return (
            round((self.x1 + self.x2) / 2.0, 6),
            round((self.y1 + self.y2) / 2.0, 6),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializa la detección y su trayectoria a un diccionario JSON para WebSocket.

        Returns:
            Diccionario con coordenadas normalizadas, ID de seguimiento, ruta y confianza.
        """
        pies_x, pies_y = self.punto_pies
        cx, cy = self.centroide
        return {
            "x1": round(self.x1, 4),
            "y1": round(self.y1, 4),
            "x2": round(self.x2, 4),
            "y2": round(self.y2, 4),
            "confianza": round(self.confianza, 4),
            "clase_id": self.clase_id,
            "track_id": self.track_id,
            "trayectoria": [
                {"x": round(px, 4), "y": round(py, 4)} for px, py in self.trayectoria
            ],
            "punto_pies": {"x": round(pies_x, 4), "y": round(pies_y, 4)},
            "centroide": {"x": round(cx, 4), "y": round(cy, 4)},
        }


@dataclass(frozen=True)
class ResultadoDeteccionROI:
    """Encapsula el resultado de procesar un fotograma bajo una estrategia espacial en CPU.

    Attributes:
        detecciones: Tupla de peatones validados (y rastreados si aplica) en la región activa.
        inferencia_ms: Tiempo conjunto de ejecución (detector + rastreador) en milisegundos.
        area_cerco_pct: Porcentaje de la escena cubierto por el polígono activo.
        imgsz_usado: Resolución cuadrada (múltiplo de 32) empleada en la inferencia CPU.
        dispositivo: Dispositivo de ejecución utilizado (siempre 'cpu' por RNF-01).
        cerco_activo: Indica si existía un cerco válido de 4 a 6 vértices durante el ciclo.
    """

    detecciones: Tuple[DeteccionPeaton, ...]
    inferencia_ms: float
    area_cerco_pct: float
    imgsz_usado: int
    dispositivo: str = "cpu"
    cerco_activo: bool = True

    @property
    def peatones_detectados(self) -> int:
        """Cantidad total de personas detectadas/rastreadas dentro de la región delimitada."""
        return len(self.detecciones)

    def to_dict(self) -> dict[str, Any]:
        """Serializa el resultado de inferencia para el evento WebSocket 'resultado_deteccion'.

        Returns:
            Diccionario listo para envío JSON al cliente web.
        """
        return {
            "cerco_activo": self.cerco_activo,
            "detecciones": [d.to_dict() for d in self.detecciones],
            "peatones_detectados": self.peatones_detectados,
            "inferencia_ms": round(self.inferencia_ms, 2),
            "area_cerco_pct": round(self.area_cerco_pct, 2),
            "imgsz": self.imgsz_usado,
            "dispositivo": self.dispositivo,
        }


@runtime_checkable
class IDetectorPeatones(Protocol):
    """Puerto de dominio para motores de detección de peatones sobre CPU y memoria RAM."""

    @property
    def dispositivo(self) -> str:
        """Identificador del dispositivo de cómputo (debe ser 'cpu' según RNF-01)."""
        ...

    def detectar_personas(
        self,
        imagen: Any,
        imgsz: int = 640,
        conf_min: float = 0.35,
    ) -> Sequence[CajaDeteccionCruda]:
        """Ejecuta inferencia sobre una imagen o recorte ROI identificando solo personas."""
        ...


@runtime_checkable
class IRastreadorPeatones(Protocol):
    """Puerto de dominio para motores de seguimiento multi-objeto por sesión (US-05 / RF-08)."""

    def actualizar(
        self,
        detecciones: Sequence[DeteccionPeaton],
    ) -> Tuple[DeteccionPeaton, ...]:
        """Asocia las detecciones actuales con pistas existentes y actualiza sus trayectorias.

        Args:
            detecciones: Candidatos reproyectados en coordenadas globales [0.0, 1.0].

        Returns:
            Tupla de `DeteccionPeaton` enriquecida con `track_id` y `trayectoria`.
        """
        ...

    def reiniciar(self) -> None:
        """Limpia todas las pistas e historiales activos en memoria de la sesión."""
        ...
