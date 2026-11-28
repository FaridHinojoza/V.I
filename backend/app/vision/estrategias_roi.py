"""Patrón Strategy de procesamiento espacial: EstrategiaCercoVirtual y EstrategiaEscenaCompleta.

Implementa el aislamiento espacial pre-inferencia sobre el polígono de 4 a 6 vértices
con margen de preservación de figura humana (RNF-02), escalado dinámico de resolución
múltiplo de 32 para acelerar la inferencia en CPU (RF-07, RNF-01) y filtrado geométrico
exacto Point-in-Polygon (US-04 / CP-04).
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, List, Sequence, Tuple

from backend.app.domain.cerco_virtual import CercoVirtualEnMemoria
from backend.app.domain.ports import (
    CajaDeteccionCruda,
    DeteccionPeaton,
    IDetectorPeatones,
    IRastreadorPeatones,
    ResultadoDeteccionROI,
)

# Constantes de alineación de red neuronal convolucional (stride máximo de YOLO = 32)
_STRIDE_YOLO: int = 32
_IMGSZ_MINIMO: int = 160
_IMGSZ_MAXIMO_DEFAULT: int = 640
_CLASE_PERSONA_COCO: int = 0


@dataclass(frozen=True)
class RecorteEspacialROI:
    """Geometría en píxeles del recorte rectangular expandido (RNF-02) sobre el fotograma.

    Attributes:
        x1_px: Coordenada izquierda del recorte en píxeles enteros.
        y1_px: Coordenada superior del recorte en píxeles enteros.
        x2_px: Coordenada derecha del recorte en píxeles enteros.
        y2_px: Coordenada inferior del recorte en píxeles enteros.
        ancho_frame: Ancho total del fotograma original en píxeles.
        alto_frame: Alto total del fotograma original en píxeles.
        imgsz_optimo: Resolución cuadrada múltiplo de 32 calculada para YOLO en CPU.
    """

    x1_px: int
    y1_px: int
    x2_px: int
    y2_px: int
    ancho_frame: int
    alto_frame: int
    imgsz_optimo: int

    @property
    def ancho_recorte(self) -> int:
        """Ancho efectivo en píxeles de la subregión recortada."""
        return max(1, self.x2_px - self.x1_px)

    @property
    def alto_recorte(self) -> int:
        """Alto efectivo en píxeles de la subregión recortada."""
        return max(1, self.y2_px - self.y1_px)


def calcular_imgsz_dinamico(
    ancho_roi: int,
    alto_roi: int,
    imgsz_min: int = _IMGSZ_MINIMO,
    imgsz_max: int = _IMGSZ_MAXIMO_DEFAULT,
) -> int:
    """Calcula la resolución óptima de entrada (múltiplo de 32) proporcional al recorte.

    Por qué: Las arquitecturas YOLOv11 reducen espacialmente los mapas de características
    hasta un factor de 32 (stride 32). Si el cerco virtual cubre una fracción pequeña del
    fotograma, reducir `imgsz` al múltiplo de 32 inmediatamente superior al lado mayor del
    recorte disminuye cuadráticamente las operaciones de punto flotante (FLOPs) en CPU
    sin reescalar innecesariamente la región a 640x640 (RF-07 / RNF-01).

    Args:
        ancho_roi: Ancho en píxeles del recorte espacial.
        alto_roi: Alto en píxeles del recorte espacial.
        imgsz_min: Límite inferior permitido (mínimo 160 px para preservar rasgos humanos).
        imgsz_max: Límite superior permitido (por defecto 640 px).

    Returns:
        Entero múltiplo de 32 dentro del rango [imgsz_min, imgsz_max].
    """
    lado_mayor = max(1, ancho_roi, alto_roi)
    multiplo_32 = ((lado_mayor + _STRIDE_YOLO - 1) // _STRIDE_YOLO) * _STRIDE_YOLO
    limite_inf = ((max(32, imgsz_min) + _STRIDE_YOLO - 1) // _STRIDE_YOLO) * _STRIDE_YOLO
    limite_sup = max(limite_inf, (imgsz_max // _STRIDE_YOLO) * _STRIDE_YOLO)
    return max(limite_inf, min(limite_sup, multiplo_32))


def obtener_dimensiones_imagen(imagen: Any) -> Tuple[int, int]:
    """Extrae (ancho, alto) en píxeles desde un ndarray de OpenCV/NumPy o contenedor en memoria.

    Args:
        imagen: Matriz numpy.ndarray con atributo `.shape` (alto, ancho, ...) o descriptor.

    Returns:
        Tupla (ancho_frame, alto_frame) en píxeles enteros.

    Raises:
        ValueError: Si la imagen es nula o carece de dimensiones espaciales válidas.
    """
    if imagen is None:
        raise ValueError("La imagen suministrada al pipeline de visión no puede ser None.")

    shape = getattr(imagen, "shape", None)
    if isinstance(shape, (tuple, list)) and len(shape) >= 2:
        alto = int(shape[0])
        ancho = int(shape[1])
        if ancho > 0 and alto > 0:
            return (ancho, alto)

    if isinstance(imagen, dict) and "ancho" in imagen and "alto" in imagen:
        ancho = int(imagen["ancho"])
        alto = int(imagen["alto"])
        if ancho > 0 and alto > 0:
            return (ancho, alto)

    raise ValueError("No se pudieron determinar las dimensiones (ancho, alto) del fotograma.")


def recortar_region_imagen(imagen: Any, recorte: RecorteEspacialROI) -> Any:
    """Aísla en memoria RAM la subregión rectangular definida por `recorte`.

    Args:
        imagen: Matriz `numpy.ndarray` (H, W, C) o representación matricial indexable.
        recorte: Coordenadas en píxeles del recorte espacial con padding RNF-02.

    Returns:
        Submatriz recortada lista para ser enviada al detector YOLO en CPU.
    """
    try:
        return imagen[recorte.y1_px : recorte.y2_px, recorte.x1_px : recorte.x2_px]
    except (TypeError, IndexError, KeyError):
        if isinstance(imagen, dict):
            return {
                "ancho": recorte.ancho_recorte,
                "alto": recorte.alto_recorte,
                "offset_x": recorte.x1_px,
                "offset_y": recorte.y1_px,
            }
        return imagen


class EstrategiaCercoVirtual:
    """Estrategia de aislamiento espacial para detección sobre el cerco de 4 a 6 vértices.

    Cumple estrictamente:
    - RF-07: Aísla el área del cerco y ejecuta YOLO sobre CPU y RAM.
    - RNF-02: Expande el bounding box del polígono con padding asimétrico para conservar
      completa la silueta (cabeza, torso y extremidades) de los peatones cercanos al borde.
    - US-04: Filtra geométricamente con Ray-casting (Point-in-Polygon) para identificar
      exclusivamente personas dentro del área delimitada.
    """

    def __init__(
        self,
        padding_pct: float = 0.15,
        imgsz_max: int = _IMGSZ_MAXIMO_DEFAULT,
        conf_min: float = 0.35,
    ) -> None:
        """Inicializa la estrategia con parámetros de margen espacial y confianza.

        Args:
            padding_pct: Fracción de margen base [0.0, 0.50] alrededor del cerco (RNF-02).
            imgsz_max: Resolución máxima de inferencia en CPU (múltiplo de 32).
            conf_min: Umbral mínimo de confianza para retener detecciones de clase persona.
        """
        self._padding_pct = max(0.0, min(0.50, float(padding_pct)))
        self._imgsz_max = max(_IMGSZ_MINIMO, int(imgsz_max))
        self._conf_min = max(0.05, min(0.99, float(conf_min)))

    def calcular_recorte_roi(
        self,
        cerco: CercoVirtualEnMemoria,
        ancho_frame: int,
        alto_frame: int,
    ) -> RecorteEspacialROI:
        """Calcula la ventana de recorte en píxeles con margen de preservación humana (RNF-02).

        Por qué se aplica padding asimétrico:
        Cuando los pies de un peatón se ubican dentro del polígono del cerco virtual, su
        torso y cabeza se proyectan verticalmente hacia arriba (menor coordenada Y). Un
        recorte estricto sobre los vértices amputaría la mitad superior del cuerpo e
        impediría que las capas convolucionales de YOLO reconozcan la clase `person`.

        Args:
            cerco: Instancia activa del cerco virtual de 4 a 6 vértices en memoria.
            ancho_frame: Ancho del fotograma completo en píxeles (> 0).
            alto_frame: Alto del fotograma completo en píxeles (> 0).

        Returns:
            Objeto `RecorteEspacialROI` con límites en píxeles e `imgsz_optimo`.

        Raises:
            ValueError: Si el cerco no está cerrado o las dimensiones son inválidas.
        """
        if ancho_frame <= 0 or alto_frame <= 0:
            raise ValueError("Las dimensiones del fotograma deben ser mayores que cero.")

        bbox = cerco.obtener_bounding_box()
        if bbox is None or not cerco.esta_cerrado:
            raise ValueError("El cerco virtual debe estar cerrado (4 a 6 vértices) para aislar ROI.")

        min_x, min_y, max_x, max_y = bbox

        # Margen asimétrico RNF-02: mayor expansión superior para preservar cabeza y torso
        pad_x = self._padding_pct
        pad_y_superior = max(self._padding_pct * 1.5, 0.18) if self._padding_pct > 0 else 0.0
        pad_y_inferior = max(self._padding_pct * 0.5, 0.05) if self._padding_pct > 0 else 0.0

        norm_x1 = max(0.0, min_x - pad_x)
        norm_y1 = max(0.0, min_y - pad_y_superior)
        norm_x2 = min(1.0, max_x + pad_x)
        norm_y2 = min(1.0, max_y + pad_y_inferior)

        x1_px = int(round(norm_x1 * ancho_frame))
        y1_px = int(round(norm_y1 * alto_frame))
        x2_px = int(round(norm_x2 * ancho_frame))
        y2_px = int(round(norm_y2 * alto_frame))

        # Garantizar ventana mínima no degenerada dentro de los límites del fotograma
        if x2_px <= x1_px:
            x2_px = min(ancho_frame, x1_px + 1)
        if y2_px <= y1_px:
            y2_px = min(alto_frame, y1_px + 1)

        imgsz_optimo = calcular_imgsz_dinamico(
            ancho_roi=x2_px - x1_px,
            alto_roi=y2_px - y1_px,
            imgsz_max=self._imgsz_max,
        )

        return RecorteEspacialROI(
            x1_px=x1_px,
            y1_px=y1_px,
            x2_px=x2_px,
            y2_px=y2_px,
            ancho_frame=ancho_frame,
            alto_frame=alto_frame,
            imgsz_optimo=imgsz_optimo,
        )

    def _reproyectar_candidatos(
        self,
        cajas_crudas: Sequence[CajaDeteccionCruda],
        recorte: RecorteEspacialROI,
        umbral_confianza: float,
    ) -> Tuple[DeteccionPeaton, ...]:
        """Transforma cajas locales del recorte al sistema global normalizado [0.0, 1.0]."""
        reproyectadas: List[DeteccionPeaton] = []
        inv_ancho = 1.0 / float(recorte.ancho_frame)
        inv_alto = 1.0 / float(recorte.alto_frame)

        for caja in cajas_crudas:
            if int(caja.clase_id) != _CLASE_PERSONA_COCO:
                continue
            if float(caja.confianza) < umbral_confianza:
                continue

            gx1 = max(0.0, min(1.0, (recorte.x1_px + float(caja.x1)) * inv_ancho))
            gy1 = max(0.0, min(1.0, (recorte.y1_px + float(caja.y1)) * inv_alto))
            gx2 = max(0.0, min(1.0, (recorte.x1_px + float(caja.x2)) * inv_ancho))
            gy2 = max(0.0, min(1.0, (recorte.y1_px + float(caja.y2)) * inv_alto))
            if gx2 <= gx1 or gy2 <= gy1:
                continue

            reproyectadas.append(
                DeteccionPeaton(
                    x1=round(gx1, 6),
                    y1=round(gy1, 6),
                    x2=round(gx2, 6),
                    y2=round(gy2, 6),
                    confianza=round(float(caja.confianza), 4),
                    clase_id=_CLASE_PERSONA_COCO,
                )
            )
        return tuple(reproyectadas)

    @staticmethod
    def _filtrar_en_poligono(
        candidatos: Sequence[DeteccionPeaton],
        cerco: CercoVirtualEnMemoria,
    ) -> Tuple[DeteccionPeaton, ...]:
        """Retiene únicamente los peatones cuyo punto de pies o centroide yace en el cerco."""
        if not cerco.esta_cerrado:
            return ()
        dentro: List[DeteccionPeaton] = []
        for candidato in candidatos:
            pies_x, pies_y = candidato.punto_pies
            cx, cy = candidato.centroide
            if cerco.punto_dentro(pies_x, pies_y) or cerco.punto_dentro(cx, cy):
                dentro.append(candidato)
        return tuple(dentro)

    def reproyectar_y_filtrar(
        self,
        cajas_crudas: Sequence[CajaDeteccionCruda],
        recorte: RecorteEspacialROI,
        cerco: CercoVirtualEnMemoria,
    ) -> Tuple[DeteccionPeaton, ...]:
        """Transforma coordenadas del recorte al cuadro global y filtra con Point-in-Polygon."""
        if not cerco.esta_cerrado:
            return ()
        candidatos = self._reproyectar_candidatos(cajas_crudas, recorte, self._conf_min)
        return self._filtrar_en_poligono(candidatos, cerco)

    def procesar(
        self,
        imagen: Any,
        cerco: CercoVirtualEnMemoria,
        detector: IDetectorPeatones,
        rastreador: IRastreadorPeatones | None = None,
    ) -> ResultadoDeteccionROI:
        """Ejecuta aislamiento ROI, detección YOLO en CPU, seguimiento ByteTrack y filtrado.

        Args:
            imagen: Fotograma completo en memoria RAM.
            cerco: Cerco virtual dinámico de 4 a 6 vértices de la sesión activa.
            detector: Implementación de `IDetectorPeatones` operando en CPU.
            rastreador: Instancia opcional `IRastreadorPeatones` (ByteTrack US-05 / RF-08).

        Returns:
            `ResultadoDeteccionROI` con `inferencia_ms` midiendo detector + rastreador.
        """
        if not cerco.esta_cerrado:
            return ResultadoDeteccionROI(
                detecciones=(),
                inferencia_ms=0.0,
                area_cerco_pct=0.0,
                imgsz_usado=0,
                dispositivo=detector.dispositivo,
                cerco_activo=False,
            )

        ancho_frame, alto_frame = obtener_dimensiones_imagen(imagen)
        recorte = self.calcular_recorte_roi(cerco, ancho_frame, alto_frame)
        subimagen = recortar_region_imagen(imagen, recorte)

        conf_consulta = (
            min(self._conf_min, float(getattr(rastreador, "conf_baja", self._conf_min)))
            if rastreador is not None
            else self._conf_min
        )

        t_inicio = time.perf_counter()
        cajas_locales = detector.detectar_personas(
            imagen=subimagen,
            imgsz=recorte.imgsz_optimo,
            conf_min=conf_consulta,
        )
        if rastreador is not None:
            candidatos_globales = self._reproyectar_candidatos(
                cajas_locales, recorte, conf_consulta
            )
            rastreados = rastreador.actualizar(candidatos_globales)
            peatones_filtrados = self._filtrar_en_poligono(rastreados, cerco)
        else:
            peatones_filtrados = self.reproyectar_y_filtrar(cajas_locales, recorte, cerco)

        inferencia_ms = (time.perf_counter() - t_inicio) * 1000.0

        return ResultadoDeteccionROI(
            detecciones=peatones_filtrados,
            inferencia_ms=round(inferencia_ms, 2),
            area_cerco_pct=cerco.calcular_porcentaje_area(),
            imgsz_usado=recorte.imgsz_optimo,
            dispositivo=detector.dispositivo,
            cerco_activo=True,
        )


class EstrategiaEscenaCompleta:
    """Estrategia de referencia que procesa el 100 % del fotograma sin recorte espacial.

    Utilizada para contrastar el costo computacional de CPU y RAM frente a
    `EstrategiaCercoVirtual` en pruebas comparativas.
    """

    def __init__(
        self,
        imgsz: int = _IMGSZ_MAXIMO_DEFAULT,
        conf_min: float = 0.35,
    ) -> None:
        """Inicializa la estrategia de escena completa.

        Args:
            imgsz: Resolución de entrada a YOLO (por defecto 640 px).
            conf_min: Umbral mínimo de confianza [0.05, 0.99].
        """
        self._imgsz = calcular_imgsz_dinamico(imgsz, imgsz, imgsz_max=imgsz)
        self._conf_min = max(0.05, min(0.99, float(conf_min)))

    def procesar(
        self,
        imagen: Any,
        detector: IDetectorPeatones,
        cerco_referencia: CercoVirtualEnMemoria | None = None,
        rastreador: IRastreadorPeatones | None = None,
    ) -> ResultadoDeteccionROI:
        """Ejecuta YOLO (y ByteTrack opcional) sobre el 100 % del fotograma sin recorte."""
        ancho_frame, alto_frame = obtener_dimensiones_imagen(imagen)
        recorte_total = RecorteEspacialROI(
            x1_px=0,
            y1_px=0,
            x2_px=ancho_frame,
            y2_px=alto_frame,
            ancho_frame=ancho_frame,
            alto_frame=alto_frame,
            imgsz_optimo=self._imgsz,
        )
        conf_consulta = (
            min(self._conf_min, float(getattr(rastreador, "conf_baja", self._conf_min)))
            if rastreador is not None
            else self._conf_min
        )
        estrategia_aux = EstrategiaCercoVirtual(conf_min=self._conf_min)

        t_inicio = time.perf_counter()
        cajas = detector.detectar_personas(
            imagen=imagen,
            imgsz=self._imgsz,
            conf_min=conf_consulta,
        )
        candidatos = estrategia_aux._reproyectar_candidatos(
            cajas, recorte_total, conf_consulta
        )
        if rastreador is not None:
            candidatos = rastreador.actualizar(candidatos)

        if cerco_referencia is not None and cerco_referencia.esta_cerrado:
            peatones = estrategia_aux._filtrar_en_poligono(candidatos, cerco_referencia)
        else:
            peatones = tuple(c for c in candidatos if c.confianza >= self._conf_min)
        inferencia_ms = (time.perf_counter() - t_inicio) * 1000.0

        return ResultadoDeteccionROI(
            detecciones=peatones,
            inferencia_ms=round(inferencia_ms, 2),
            area_cerco_pct=100.0,
            imgsz_usado=self._imgsz,
            dispositivo=detector.dispositivo,
            cerco_activo=True,
        )
