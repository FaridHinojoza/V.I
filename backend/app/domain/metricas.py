"""Modelos de valor de dominio para las ocho métricas computacionales (RF-11 / US-05 / V 1.2).

Define la estructura tipada e inmutable de telemetría operativa compartida entre
Monitoreo en Vivo (/ws/monitoreo) y Modo Evaluación Experimental (/api/evaluacion/mp4),
conforme a las Tablas 4 y 10 de Requisitos_Sistema_VI V 1.2.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MetricasOperativas:
    """Representa las 8 métricas computacionales instantáneas o promediadas del sistema V.I.

    Las cuatro métricas adicionales de efectividad operativa (Precisión, Sensibilidad,
    Puntaje F1 y Exactitud) son exclusivas del Modo Evaluación con Ground Truth (US-09),
    por lo que este objeto modela estrictamente el desempeño computacional y conteo.

    Attributes:
        fps: Velocidad de procesamiento en cuadros por segundo (>= 0.0).
        inferencia_ms: Latencia conjunta de detector YOLO + rastreador ByteTrack en ms (>= 0.0).
        area_cerco_pct: Porcentaje del fotograma cubierto por el cerco de 4 a 6 vértices [0..100].
        cpu_pct: Porcentaje de uso de procesador CPU del servidor [0..100].
        ram_mb: Consumo de memoria RAM residente del servidor en megabytes (>= 0.0).
        gpu_pct: Porcentaje de uso de GPU [0..100] (0.0 % bajo ejecución CPU pura RNF-01).
        ancho_banda_kbs: Tasa de transferencia del payload en kilobytes por segundo (>= 0.0).
        peatones: Cantidad de peatones rastreados actualmente dentro de la zona activa (>= 0).
        alertas: Total acumulado de alertas de merodeo confirmadas en la sesión (>= 0).
    """

    fps: float = 0.0
    inferencia_ms: float = 0.0
    area_cerco_pct: float = 0.0
    cpu_pct: float = 0.0
    ram_mb: float = 0.0
    gpu_pct: float = 0.0
    ancho_banda_kbs: float = 0.0
    peatones: int = 0
    alertas: int = 0

    @classmethod
    def iniciales(cls) -> MetricasOperativas:
        """Construye un estado en cero para el arranque o reinicio de una sesión."""
        return cls()

    def to_dict(self) -> dict[str, Any]:
        """Serializa las 8 métricas computacionales al contrato JSON del canal WebSocket.

        Returns:
            Diccionario con valores numéricos redondeados listos para emisión en vivo.
        """
        return {
            "fps": round(max(0.0, float(self.fps)), 1),
            "inferencia_ms": round(max(0.0, float(self.inferencia_ms)), 2),
            "area_cerco_pct": round(min(100.0, max(0.0, float(self.area_cerco_pct))), 2),
            "cpu_pct": round(min(100.0, max(0.0, float(self.cpu_pct))), 1),
            "ram_mb": round(max(0.0, float(self.ram_mb)), 1),
            "gpu_pct": round(min(100.0, max(0.0, float(self.gpu_pct))), 1),
            "ancho_banda_kbs": round(max(0.0, float(self.ancho_banda_kbs)), 1),
            "peatones": max(0, int(self.peatones)),
            "alertas": max(0, int(self.alertas)),
        }
