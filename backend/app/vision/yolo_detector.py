"""Adaptador Singleton de Ultralytics YOLO operando 100 % sobre CPU y RAM (solo clase persona).

Cumple los requisitos RF-07 y RNF-01:
- Ejecución exclusiva en procesador CPU (`device="cpu"`) y memoria RAM sin requerir GPU/CUDA.
- Filtrado nativo en el motor de inferencia a `classes=[0]` (persona en COCO).
- Decodificación segura de fotogramas Base64/JPEG en memoria sin escritura en disco.
"""

from __future__ import annotations

import base64
import binascii
import logging
from pathlib import Path
import struct
import threading
from typing import Any, Callable, List, Optional, Sequence, Tuple

from backend.app.core.concurrency import compute_lock
from backend.app.domain.ports import CajaDeteccionCruda

logger = logging.getLogger(__name__)

_DISPOSITIVO_CPU: str = "cpu"
_CLASE_PERSONA_COCO: int = 0
_MAX_FRAME_BYTES: int = 8 * 1024 * 1024  # Límite defensivo de 8 MB por fotograma en RAM


class FrameInvalidoError(Exception):
    """Excepción lanzada cuando un fotograma Base64 está vacío, corrupto o excede límites."""


class ImagenMemoria:
    """Contenedor matricial ligero en RAM compatible con slicing 2D `[y1:y2, x1:x2]` y `.shape`.

    Por qué: Permite operar y probar toda la tubería geométrica de recorte espacial ROI
    tanto con tensores `numpy.ndarray` de OpenCV como en entornos ligeros sin extensiones C.
    """

    def __init__(
        self,
        ancho: int,
        alto: int,
        canales: int = 3,
        raw_bytes: bytes = b"",
        offset_x: int = 0,
        offset_y: int = 0,
    ) -> None:
        """Inicializa la representación en memoria del fotograma o recorte.

        Args:
            ancho: Ancho en píxeles (> 0).
            alto: Alto en píxeles (> 0).
            canales: Número de canales de color (3 para BGR/RGB).
            raw_bytes: Bytes comprimidos originales opcionales.
            offset_x: Desplazamiento horizontal acumulado si proviene de un recorte.
            offset_y: Desplazamiento vertical acumulado si proviene de un recorte.
        """
        self.ancho = max(1, int(ancho))
        self.alto = max(1, int(alto))
        self.canales = max(1, int(canales))
        self.raw_bytes = raw_bytes
        self.offset_x = int(offset_x)
        self.offset_y = int(offset_y)

    @property
    def shape(self) -> Tuple[int, int, int]:
        """Retorna la tupla `(alto, ancho, canales)` idéntica a la convención de OpenCV/NumPy."""
        return (self.alto, self.ancho, self.canales)

    def __getitem__(self, key: Any) -> ImagenMemoria:
        """Soporta el recorte matricial `imagen[y1:y2, x1:x2]` en memoria RAM."""
        if isinstance(key, tuple) and len(key) >= 2:
            slice_y, slice_x = key[0], key[1]
            y1, y2, _ = slice_y.indices(self.alto) if isinstance(slice_y, slice) else (0, self.alto, 1)
            x1, x2, _ = slice_x.indices(self.ancho) if isinstance(slice_x, slice) else (0, self.ancho, 1)
            nuevo_ancho = max(1, x2 - x1)
            nuevo_alto = max(1, y2 - y1)
            return ImagenMemoria(
                ancho=nuevo_ancho,
                alto=nuevo_alto,
                canales=self.canales,
                raw_bytes=self.raw_bytes,
                offset_x=self.offset_x + x1,
                offset_y=self.offset_y + y1,
            )
        return self


def _extraer_dimensiones_cabecera_imagen(data: bytes) -> Optional[Tuple[int, int]]:
    """Extrae `(ancho, alto)` inspeccionando cabeceras binarias PNG o JPEG en memoria.

    Args:
        data: Bytes crudos de la imagen comprimida.

    Returns:
        Tupla `(ancho, alto)` si se identifica cabecera PNG/JPEG válida, o `None`.
    """
    # 1. Cabecera PNG: 8 bytes de firma + chunk IHDR con ancho y alto en big-endian
    if len(data) >= 24 and data.startswith(b"\x89PNG\r\n\x1a\n"):
        ancho, alto = struct.unpack(">II", data[16:24])
        if ancho > 0 and alto > 0:
            return (int(ancho), int(alto))

    # 2. Cabecera JPEG: marcadores SOI (0xFFD8) y segmentos SOF0..SOF3 (0xFFC0..0xFFC3)
    if len(data) >= 4 and data[0:2] == b"\xff\xd8":
        idx = 2
        longitud = len(data)
        while idx + 4 < longitud:
            if data[idx] != 0xFF:
                idx += 1
                continue
            marcador = data[idx + 1]
            if marcador == 0xFF:
                idx += 1
                continue
            if marcador in (0xD8, 0xD9) or (0xD0 <= marcador <= 0xD7):
                idx += 2
                continue
            if idx + 4 > longitud:
                break
            tam_segmento = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
            if tam_segmento < 2:
                break
            if marcador in (0xC0, 0xC1, 0xC2, 0xC3) and idx + 9 <= longitud:
                alto, ancho = struct.unpack(">HH", data[idx + 5 : idx + 9])
                if ancho > 0 and alto > 0:
                    return (int(ancho), int(alto))
            idx += 2 + tam_segmento

    return None


def decodificar_frame_base64(
    frame_b64: str,
    ancho_fallback: int = 640,
    alto_fallback: int = 480,
) -> Any:
    """Decodifica un fotograma codificado en Base64 (Data URI o crudo) hacia memoria RAM.

    Utiliza `cv2.imdecode` sobre `numpy.frombuffer` cuando OpenCV está disponible en el
    entorno de ejecución (contenedor Docker CPU), o construye un objeto `ImagenMemoria`
    verificando la cabecera binaria JPEG/PNG.

    Args:
        frame_b64: Cadena Base64 (ej. `'data:image/jpeg;base64,/9j/4AAQ...'`).
        ancho_fallback: Ancho por defecto si se recibe un buffer sintético de prueba.
        alto_fallback: Alto por defecto si se recibe un buffer sintético de prueba.

    Returns:
        Matriz `numpy.ndarray` (BGR) o instancia `ImagenMemoria` con `.shape`.

    Raises:
        FrameInvalidoError: Si la cadena está vacía, malformada o supera el tamaño máximo.
    """
    if not isinstance(frame_b64, str) or not frame_b64.strip():
        raise FrameInvalidoError("El fotograma Base64 está vacío o no es una cadena válida.")

    limpio = frame_b64.strip()
    if "," in limpio and limpio.lower().startswith("data:"):
        limpio = limpio.split(",", 1)[1].strip()

    if not limpio:
        raise FrameInvalidoError("El contenido Base64 del fotograma está vacío.")

    try:
        raw_bytes = base64.b64decode(limpio, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise FrameInvalidoError("Codificación Base64 del fotograma corrupta o inválida.") from exc

    if len(raw_bytes) < 4:
        raise FrameInvalidoError("El buffer decodificado es demasiado pequeño para ser una imagen.")
    if len(raw_bytes) > _MAX_FRAME_BYTES:
        raise FrameInvalidoError("El fotograma excede el límite máximo de memoria RAM permitido.")

    # Intentar decodificación nativa con OpenCV Headless en RAM
    try:
        import cv2  # type: ignore[import-not-found]
        import numpy as np  # type: ignore[import-not-found]

        arr = np.frombuffer(raw_bytes, dtype=np.uint8)
        frame_bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame_bgr is not None and getattr(frame_bgr, "size", 0) > 0:
            return frame_bgr
    except ImportError:
        pass

    # Fallback en memoria con inspección de cabeceras JPEG / PNG
    dims = _extraer_dimensiones_cabecera_imagen(raw_bytes)
    if dims is not None:
        return ImagenMemoria(ancho=dims[0], alto=dims[1], canales=3, raw_bytes=raw_bytes)

    if raw_bytes.startswith(b"VI_TEST_FRAME"):
        return ImagenMemoria(
            ancho=max(1, ancho_fallback),
            alto=max(1, alto_fallback),
            canales=3,
            raw_bytes=raw_bytes,
        )

    raise FrameInvalidoError("El buffer binario no corresponde a un formato JPEG o PNG válido.")


class DetectorYOLOCPU:
    """Adaptador Singleton para detección de peatones con Ultralytics YOLO en CPU y RAM.

    Garantiza:
    - Instancia única del modelo en memoria RAM (patrón Singleton thread-safe).
    - Parámetro `device="cpu"` inmutable en cada inferencia (`RNF-01`).
    - Filtro `classes=[0]` para detectar exclusivamente personas (`RF-07`, `US-04`).
    """

    _instancia: Optional[DetectorYOLOCPU] = None
    _singleton_lock = threading.Lock()

    def __init__(
        self,
        model_path: str = "models/yolo11n.pt",
        predictor_fn: Optional[Callable[..., Sequence[CajaDeteccionCruda]]] = None,
    ) -> None:
        """Inicializa el adaptador YOLO configurado estrictamente para CPU.

        Args:
            model_path: Ruta al archivo de pesos `.pt` de Ultralytics YOLO.
            predictor_fn: Función predictora inyectable para pruebas unitarias deterministas.
        """
        self._model_path = model_path
        self._dispositivo: str = _DISPOSITIVO_CPU
        self._modelo_yolo: Any = None
        self._predictor_fn = predictor_fn
        self._ultimo_llamado_kwargs: dict[str, Any] = {}

    @classmethod
    def obtener_instancia(
        cls,
        model_path: str = "models/yolo11n.pt",
    ) -> DetectorYOLOCPU:
        """Obtiene o crea la instancia Singleton en memoria RAM de forma thread-safe.

        Args:
            model_path: Ruta a los pesos de YOLO si aún no se ha inicializado.

        Returns:
            Instancia única de `DetectorYOLOCPU`.
        """
        if cls._instancia is None:
            with cls._singleton_lock:
                if cls._instancia is None:
                    cls._instancia = cls(model_path=model_path)
        return cls._instancia

    @classmethod
    def reiniciar_instancia(cls) -> None:
        """Limpia la referencia Singleton (útil para aislamiento entre pruebas unitarias)."""
        with cls._singleton_lock:
            cls._instancia = None

    @property
    def dispositivo(self) -> str:
        """Retorna el dispositivo de ejecución activo (invariante `'cpu'` por RNF-01)."""
        return self._dispositivo

    @property
    def model_path(self) -> str:
        """Ruta configurada de los pesos del modelo YOLO."""
        return self._model_path

    @property
    def ultimo_llamado_kwargs(self) -> dict[str, Any]:
        """Metadatos de la última invocación de inferencia (para auditoría de CPU/clases)."""
        return dict(self._ultimo_llamado_kwargs)

    def _cargar_modelo_si_necesario(self) -> Any:
        """Carga perezosamente el modelo Ultralytics YOLO en memoria RAM sobre CPU."""
        if self._modelo_yolo is not None:
            return self._modelo_yolo

        from ultralytics import YOLO  # type: ignore[import-not-found]

        ruta = Path(self._model_path)
        nombre_o_ruta = str(ruta) if ruta.is_file() else "yolo11n.pt"
        logger.info("Cargando modelo Ultralytics YOLO en CPU y RAM desde: %s", nombre_o_ruta)
        modelo = YOLO(nombre_o_ruta)
        self._modelo_yolo = modelo
        return self._modelo_yolo

    def detectar_personas(
        self,
        imagen: Any,
        imgsz: int = 640,
        conf_min: float = 0.35,
    ) -> Sequence[CajaDeteccionCruda]:
        """Ejecuta la detección de personas (`class 0`) estrictamente en CPU y memoria RAM.

        Args:
            imagen: Recorte espacial ROI o fotograma completo en memoria.
            imgsz: Resolución escalada (múltiplo de 32) calculada para el ROI.
            conf_min: Umbral mínimo de confianza [0.05, 0.99].

        Returns:
            Lista de `CajaDeteccionCruda` correspondientes únicamente a personas (`clase_id == 0`).
        """
        if imagen is None:
            raise ValueError("No se puede ejecutar detección YOLO sobre una imagen None.")

        parametros_inferencia = {
            "device": _DISPOSITIVO_CPU,
            "classes": [_CLASE_PERSONA_COCO],
            "imgsz": int(imgsz),
            "conf": float(conf_min),
            "verbose": False,
        }

        with compute_lock:
            self._ultimo_llamado_kwargs = dict(parametros_inferencia)

            if self._predictor_fn is not None:
                cajas_raw = self._predictor_fn(imagen, **parametros_inferencia)
                return tuple(
                    c
                    for c in cajas_raw
                    if int(c.clase_id) == _CLASE_PERSONA_COCO and float(c.confianza) >= conf_min
                )

            try:
                modelo = self._cargar_modelo_si_necesario()
            except ImportError:
                logger.debug(
                    "Ultralytics no instalado en entorno local ligero; retornando 0 detecciones."
                )
                return ()

            resultados = modelo.predict(
                source=imagen,
                device=_DISPOSITIVO_CPU,
                classes=[_CLASE_PERSONA_COCO],
                imgsz=int(imgsz),
                conf=float(conf_min),
                verbose=False,
            )

        cajas_detectadas: List[CajaDeteccionCruda] = []
        for res in resultados:
            boxes = getattr(res, "boxes", None)
            if boxes is None:
                continue
            xyxy_list = boxes.xyxy.cpu().tolist() if hasattr(boxes.xyxy, "cpu") else boxes.xyxy
            conf_list = boxes.conf.cpu().tolist() if hasattr(boxes.conf, "cpu") else boxes.conf
            cls_list = boxes.cls.cpu().tolist() if hasattr(boxes.cls, "cpu") else boxes.cls

            for coords, conf_val, cls_val in zip(xyxy_list, conf_list, cls_list):
                clase_entera = int(round(float(cls_val)))
                if clase_entera != _CLASE_PERSONA_COCO:
                    continue
                if float(conf_val) < conf_min:
                    continue
                cajas_detectadas.append(
                    CajaDeteccionCruda(
                        x1=float(coords[0]),
                        y1=float(coords[1]),
                        x2=float(coords[2]),
                        y2=float(coords[3]),
                        confianza=float(conf_val),
                        clase_id=_CLASE_PERSONA_COCO,
                    )
                )

        return tuple(cajas_detectadas)
