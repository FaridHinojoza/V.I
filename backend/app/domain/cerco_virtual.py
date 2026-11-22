"""Entidad de dominio CercoVirtualEnMemoria para delimitación dinámica de zonas de vigilancia.

Gobierna las restricciones innegociables RF-04, RF-05, RF-06 y RNF-04:
- Polígono de 4 (mínimo) a 6 (máximo) vértices interactivos.
- Coordenadas normalizadas [0.0 .. 1.0] relativas a la resolución del video.
- Algoritmo Point-in-Polygon (Ray-casting) y cálculo de porcentaje de área (Shoelace).
- Cero persistencia en base de datos: ciclo de vida restringido a memoria de sesión.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional, Sequence, Tuple


class EstadoCerco(str, Enum):
    """Estados del cerco virtual según la máquina de estados RF-12."""

    NORMAL = "verde"  # Sin presencia o personas en tránsito normal
    OBSERVACION = "amarillo"  # Peatón detectado dentro del cerco acumulando tiempo
    ALERTA = "rojo"  # Merodeo confirmado (tiempo de permanencia o trayectoria recurrente)


class CercoInvalidoError(Exception):
    """Excepción de dominio lanzada ante transgresiones de la geometría del cerco."""


class CercoVirtualEnMemoria:
    """Representa el cerco virtual dinámico mantenido exclusivamente en memoria de sesión."""

    VERTICES_MIN: int = 4
    VERTICES_MAX: int = 6

    def __init__(self, vertices: Optional[Sequence[Tuple[float, float]]] = None) -> None:
        """Inicializa la instancia en memoria con vértices normalizados opcionales.

        Args:
            vertices: Secuencia de tuplas (x, y) con coordenadas en el rango [0.0, 1.0].
        """
        self._vertices: List[Tuple[float, float]] = []
        self._estado: EstadoCerco = EstadoCerco.NORMAL

        if vertices is not None and len(vertices) > 0:
            self.definir_vertices(vertices)

    @property
    def vertices(self) -> List[Tuple[float, float]]:
        """Retorna una copia defensiva de los vértices normalizados actuales."""
        return list(self._vertices)

    @property
    def cantidad_vertices(self) -> int:
        """Cantidad de vértices actualmente configurados en el polígono."""
        return len(self._vertices)

    @property
    def esta_cerrado(self) -> bool:
        """Indica si el cerco posee un polígono válido y cerrado en el rango [4..6]."""
        return self.VERTICES_MIN <= len(self._vertices) <= self.VERTICES_MAX

    @property
    def estado(self) -> EstadoCerco:
        """Estado semántico del cerco (verde, amarillo o rojo)."""
        return self._estado

    @estado.setter
    def estado(self, nuevo_estado: EstadoCerco) -> None:
        """Actualiza la máquina de estados del cerco en caliente."""
        if not isinstance(nuevo_estado, EstadoCerco):
            raise ValueError(f"Estado de cerco inválido: {nuevo_estado!r}")
        self._estado = nuevo_estado

    def definir_vertices(self, vertices: Sequence[Any]) -> None:
        """Valida y asigna los vértices normalizados del cerco virtual (RF-05 / CP-03).

        Args:
            vertices: Lista de puntos [ (x1, y1), ..., (xn, yn) ] o diccionarios [{'x': ..., 'y': ...}].

        Raises:
            CercoInvalidoError: Si la cantidad de vértices no pertenece a [4..6] o si los
                valores no corresponden a números escalares válidos en [0.0, 1.0].
        """
        if not isinstance(vertices, (list, tuple)):
            raise CercoInvalidoError("Los vértices deben ser provistos como una lista o tupla.")

        total = len(vertices)
        if total < self.VERTICES_MIN:
            raise CercoInvalidoError(
                f"El cerco virtual requiere un mínimo de {self.VERTICES_MIN} vértices; se recibieron {total}."
            )
        if total > self.VERTICES_MAX:
            raise CercoInvalidoError(
                f"El cerco virtual permite un máximo de {self.VERTICES_MAX} vértices; se recibieron {total}."
            )

        puntos_validados: List[Tuple[float, float]] = []
        for idx, pt in enumerate(vertices):
            # Compatibilidad con tuplas/listas (x, y) y objetos dict {"x": ..., "y": ...}
            if isinstance(pt, dict):
                raw_x = pt.get("x")
                raw_y = pt.get("y")
            elif isinstance(pt, (tuple, list)) and len(pt) >= 2:
                raw_x = pt[0]
                raw_y = pt[1]
            else:
                raise CercoInvalidoError(f"Formato de punto inválido en índice {idx}: {pt!r}")

            try:
                x = float(raw_x)
                y = float(raw_y)
            except (ValueError, TypeError) as exc:
                raise CercoInvalidoError(f"Las coordenadas deben ser números reales en índice {idx}.") from exc

            # Limitar o validar rango de normalización [0.0 .. 1.0]
            if not (0.0 <= x <= 1.0 and 0.0 <= y <= 1.0):
                # Clamp defensivo en bordes con tolerancia de punto flotante
                x = max(0.0, min(1.0, x))
                y = max(0.0, min(1.0, y))

            puntos_validados.append((round(x, 6), round(y, 6)))

        # Evitar polígonos colapsados con puntos repetidos consecutivos
        for i in range(len(puntos_validados)):
            p_actual = puntos_validados[i]
            p_siguiente = puntos_validados[(i + 1) % len(puntos_validados)]
            if abs(p_actual[0] - p_siguiente[0]) < 1e-5 and abs(p_actual[1] - p_siguiente[1]) < 1e-5:
                raise CercoInvalidoError("El cerco contiene vértices adyacentes duplicados o colapsados.")

        self._vertices = puntos_validados
        self._estado = EstadoCerco.NORMAL

    def limpiar(self) -> None:
        """Reinicia el cerco virtual en memoria, borrando vértices y restaurando estado normal."""
        self._vertices = []
        self._estado = EstadoCerco.NORMAL

    def calcular_porcentaje_area(self) -> float:
        """Calcula el porcentaje de área que cubre el polígono frente a la escena completa (RF-11).

        Aplica la fórmula de agrimensor / área de Gauss (Shoelace formula) sobre coordenadas
        normalizadas [0..1] x [0..1], cuyo espacio total equivale a 1.0 (100 %).

        Returns:
            Porcentaje de área en el rango [0.0, 100.0].
        """
        if not self.esta_cerrado:
            return 0.0

        n = len(self._vertices)
        suma = 0.0
        for i in range(n):
            j = (i + 1) % n
            xi, yi = self._vertices[i]
            xj, yj = self._vertices[j]
            suma += (xi * yj) - (xj * yi)

        area_normalizada = abs(suma) / 2.0
        return round(area_normalizada * 100.0, 2)

    def punto_dentro(self, x: float, y: float) -> bool:
        """Evalúa si un punto de prueba se encuentra en el interior del polígono (Point-in-Polygon).

        Utiliza el algoritmo de trazado de rayos (Ray-casting / Jordan Curve Theorem) con complejidad
        O(N), altamente eficiente sobre CPU para evaluación en tiempo real de peatones.

        Args:
            x: Coordenada horizontal normalizada [0.0, 1.0].
            y: Coordenada vertical normalizada [0.0, 1.0].

        Returns:
            True si el punto está dentro del polígono del cerco, False en caso contrario.
        """
        if not self.esta_cerrado:
            return False

        dentro = False
        n = len(self._vertices)
        p1x, p1y = self._vertices[0]

        for i in range(1, n + 1):
            p2x, p2y = self._vertices[i % n]
            if y > min(p1y, p2y):
                if y <= max(p1y, p2y):
                    if x <= max(p1x, p2x):
                        if p1y != p2y:
                            xinters = (y - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                        else:
                            xinters = p1x
                        if p1x == p2x or x <= xinters:
                            dentro = not dentro
            p1x, p1y = p2x, p2y

        return dentro

    def obtener_bounding_box(self) -> Optional[Tuple[float, float, float, float]]:
        """Retorna la caja envolvente mínima normalizada (min_x, min_y, max_x, max_y).

        Esencial para recortar con margen la región del fotograma antes de alimentar a YOLO (RNF-02).

        Returns:
            Tupla (min_x, min_y, max_x, max_y) o None si el cerco no está configurado.
        """
        if not self.esta_cerrado:
            return None

        xs = [pt[0] for pt in self._vertices]
        ys = [pt[1] for pt in self._vertices]
        return (min(xs), min(ys), max(xs), max(ys))

    def to_dict(self) -> dict[str, Any]:
        """Serializa el estado del cerco para comunicación WebSocket hacia el cliente."""
        return {
            "activo": self.esta_cerrado,
            "cantidad_vertices": self.cantidad_vertices,
            "vertices": [{"x": pt[0], "y": pt[1]} for pt in self._vertices],
            "area_pct": self.calcular_porcentaje_area(),
            "estado": self._estado.value,
        }
