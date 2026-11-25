"""Capturador de flujos de cámara por red RTSP/HTTP sobre CPU y RAM (RF-03 / RNF-01 / CP-02).

Gestiona la validación estricta de enlaces de cámaras IP (como Hikvision RTSP),
el enmascaramiento de credenciales en bitácoras y la lectura de baja latencia
mediante OpenCV (FFmpeg sobre TCP) sin requerir aceleración por GPU.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import logging
import os
import re
import threading
import time
from typing import Any, Callable, Optional
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

_ESQUEMAS_PERMITIDOS = frozenset({"rtsp", "rtsps", "http", "https"})
_PREFIJO_IP_ERRONEO_RE = re.compile(
    r"^(?:ip)[\s_:-]*(\d{1,3}(?:\.\d{1,3}){3})$", re.IGNORECASE
)
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CARACTERES_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\s]")

# Opciones FFmpeg para transporte TCP estable y timeout de 5 segundos (5_000_000 us).
# Se usa TCP porque las cámaras IP (p. ej. Hikvision /Streaming/Channels/101) suelen
# perder paquetes clave (I-frames) por UDP en redes locales congestionadas o contenedores.
_OPCIONES_FFMPEG_TCP = "rtsp_transport;tcp|stimeout;5000000|fflags;nobuffer"


class URLCamaraInvalidaError(ValueError):
    """Excepción lanzada cuando el enlace de la cámara IP es inseguro o malformado."""


@dataclass(frozen=True)
class FotogramaCapturado:
    """Representa un fotograma decodificado en CPU listo para transmisión WebSocket.

    Attributes:
        jpeg_b64: Imagen comprimida en formato JPEG codificada en Base64 ASCII.
        ancho: Ancho efectivo del fotograma transmitido en píxeles.
        alto: Alto efectivo del fotograma transmitido en píxeles.
        fps: Velocidad instantánea suavizada de captura en cuadros por segundo.
        inferencia_ms: Latencia de procesamiento del cuadro en milisegundos.
        cpu_pct: Porcentaje de uso de CPU del proceso servidor.
        ram_mb: Consumo de memoria RAM residente (RSS) del servidor en megabytes.
    """

    jpeg_b64: str
    ancho: int
    alto: int
    fps: float
    inferencia_ms: float
    cpu_pct: float
    ram_mb: float
    frame_bgr: Optional[Any] = None


class _MonitorRecursosCPU:
    """Lector ligero de métricas del servidor mediante psutil (RNF-01 / RF-11)."""

    def __init__(self) -> None:
        self._proceso: Optional[Any] = None
        self._num_nucleos: int = max(1, os.cpu_count() or 1)
        try:
            import psutil

            self._proceso = psutil.Process(os.getpid())
            # Primera llamada de calentamiento no bloqueante para inicializar el delta de CPU
            self._proceso.cpu_percent(interval=None)
        except Exception:
            self._proceso = None

    def leer_cpu_y_ram(self) -> tuple[float, float]:
        """Obtiene el porcentaje de CPU normalizado [0..100] y la RAM en MB.

        Returns:
            Tupla (cpu_pct, ram_mb) redondeada para telemetría en vivo.
        """
        if self._proceso is None:
            return 0.0, 0.0
        try:
            cpu_raw = float(self._proceso.cpu_percent(interval=None))
            cpu_norm = min(100.0, max(0.0, cpu_raw / self._num_nucleos))
            ram_bytes = float(self._proceso.memory_info().rss)
            ram_mb = ram_bytes / (1024.0 * 1024.0)
            return round(cpu_norm, 1), round(ram_mb, 1)
        except Exception:
            return 0.0, 0.0


def _limpiar_host_y_puerto(hostport: str) -> str:
    """Valida el segmento host[:puerto] y corrige el prefijo accidental 'IP' antes de IPv4.

    Por qué: Es frecuente que los operadores copien plantillas como 'IP192.168.0.76:554'.
    Limpiar ese prefijo evita fallos DNS innecesarios manteniendo validación estricta.
    """
    if not hostport:
        raise URLCamaraInvalidaError("El enlace de la cámara debe incluir una dirección IP o host.")

    # Soporte para IPv6 entre corchetes [::1]:554
    if hostport.startswith("["):
        cierre = hostport.find("]")
        if cierre == -1:
            raise URLCamaraInvalidaError("Dirección IPv6 malformada en el enlace de cámara.")
        host = hostport[: cierre + 1]
        resto = hostport[cierre + 1 :]
        puerto_str = resto[1:] if resto.startswith(":") else ""
    elif ":" in hostport:
        host, _, puerto_str = hostport.rpartition(":")
    else:
        host, puerto_str = hostport, ""

    coincidencia_prefijo = _PREFIJO_IP_ERRONEO_RE.match(host)
    if coincidencia_prefijo:
        host = coincidencia_prefijo.group(1)

    if not host:
        raise URLCamaraInvalidaError("La dirección IP o nombre de host de la cámara está vacía.")

    coincidencia_ipv4 = _IPV4_RE.match(host)
    if coincidencia_ipv4:
        octetos = [int(grupo) for grupo in coincidencia_ipv4.groups()]
        if any(octeto < 0 or octeto > 255 for octeto in octetos):
            raise URLCamaraInvalidaError(
                f"Dirección IPv4 fuera de rango válido (0-255): '{host}'."
            )

    if puerto_str:
        if not puerto_str.isdigit():
            raise URLCamaraInvalidaError(f"Puerto de cámara inválido: '{puerto_str}'.")
        puerto = int(puerto_str)
        if not (1 <= puerto <= 65535):
            raise URLCamaraInvalidaError(
                f"El puerto de la cámara debe estar entre 1 y 65535 (recibido: {puerto})."
            )
        return f"{host}:{puerto}"

    return host


def _codificar_credenciales(userinfo: str) -> str:
    """Codifica de forma segura usuario y contraseña preservando símbolos válidos de RTSP.

    Por qué: Si la contraseña contiene '@', '#' o espacios, el parser de FFmpeg rompe la URI,
    mientras que caracteres habituales como '*' (ej. 'Espe2025*') deben conservarse legibles.
    """
    if ":" not in userinfo:
        usuario_limpio = quote(unquote(userinfo), safe="*!$-._~")
        return usuario_limpio

    usuario, _, password = userinfo.partition(":")
    usuario_cod = quote(unquote(usuario), safe="*!$-._~")
    password_cod = quote(unquote(password), safe="*!$-._~")
    return f"{usuario_cod}:{password_cod}"


def normalizar_url_camara(url_raw: str) -> str:
    """Valida y normaliza un enlace de flujo de cámara en red (RTSP/RTSPS/HTTP/HTTPS).

    Bloquea esquemas locales ('file://', rutas de disco o índices numéricos) para prevenir
    lectura arbitraria de archivos o SSRF local.

    Args:
        url_raw: Cadena ingresada por el operador en la vista de monitoreo.

    Returns:
        URL normalizada y segura lista para pasarse a OpenCV/FFmpeg.

    Raises:
        URLCamaraInvalidaError: Si la URL está vacía, usa un protocolo prohibido o es inválida.
    """
    if not isinstance(url_raw, str) or not url_raw.strip():
        raise URLCamaraInvalidaError("Debe ingresar un enlace RTSP o HTTP válido para la cámara.")

    limpia = url_raw.strip()
    if _CARACTERES_CONTROL_RE.search(limpia):
        raise URLCamaraInvalidaError(
            "El enlace de la cámara no debe contener espacios intermedios ni caracteres de control."
        )

    if "://" not in limpia:
        raise URLCamaraInvalidaError(
            "El enlace debe incluir el protocolo (por ejemplo, rtsp://usuario:clave@192.168.0.76:554/...)."
        )

    esquema_raw, _, resto = limpia.partition("://")
    esquema = esquema_raw.lower()
    if esquema not in _ESQUEMAS_PERMITIDOS:
        raise URLCamaraInvalidaError(
            f"Protocolo '{esquema}://' no permitido. Use únicamente rtsp://, rtsps://, http:// o https://."
        )

    if not resto:
        raise URLCamaraInvalidaError("El enlace de la cámara no contiene dirección de destino.")

    # Separar autoridad (credenciales@host:puerto) de la ruta (/Streaming/Channels/101)
    indice_barra = resto.find("/")
    if indice_barra == -1:
        autoridad, ruta = resto, ""
    else:
        autoridad, ruta = resto[:indice_barra], resto[indice_barra:]

    # Se usa rpartition('@') para tolerar contraseñas que contengan '@' sin romper el host
    if "@" in autoridad:
        userinfo, _, hostport = autoridad.rpartition("@")
        if not userinfo:
            raise URLCamaraInvalidaError("Credenciales incompletas antes de '@' en el enlace.")
        autoridad_final = f"{_codificar_credenciales(userinfo)}@{_limpiar_host_y_puerto(hostport)}"
    else:
        autoridad_final = _limpiar_host_y_puerto(autoridad)

    return f"{esquema}://{autoridad_final}{ruta}"


def enmascarar_url_camara(url: str) -> str:
    """Oculta la contraseña en una URL de cámara para registro seguro en logs.

    Args:
        url: Enlace original o normalizado de la cámara.

    Returns:
        Enlace con la contraseña sustituida por '***'.
    """
    if "://" not in url:
        return "<enlace-camara>"
    esquema, _, resto = url.partition("://")
    indice_barra = resto.find("/")
    autoridad = resto if indice_barra == -1 else resto[:indice_barra]
    ruta = "" if indice_barra == -1 else resto[indice_barra:]

    if "@" not in autoridad:
        return url

    userinfo, _, hostport = autoridad.rpartition("@")
    usuario = userinfo.partition(":")[0] if ":" in userinfo else userinfo
    return f"{esquema}://{usuario}:***@{hostport}{ruta}"


def _crear_video_capture_opencv(url_normalizada: str) -> Any:
    """Factoría por defecto que instancia cv2.VideoCapture sobre CPU con FFmpeg/TCP."""
    os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", _OPCIONES_FFMPEG_TCP)
    try:
        import cv2
    except ImportError as exc:
        raise ConnectionError(
            "OpenCV (opencv-python-headless) no está instalado en el entorno actual."
        ) from exc

    captura = cv2.VideoCapture(url_normalizada, cv2.CAP_FFMPEG)
    # Limitar el búfer interno a 1 fotograma evita acumular retraso de varios segundos en vivo
    try:
        captura.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    except Exception:
        pass
    return captura


def _codificar_frame_a_jpeg_b64(
    frame: Any, max_ancho: int, calidad_jpeg: int
) -> tuple[str, int, int, Any]:
    """Redimensiona opcionalmente el cuadro en CPU y lo comprime a JPEG Base64."""
    alto_orig, ancho_orig = int(frame.shape[0]), int(frame.shape[1])
    try:
        import cv2

        frame_salida = frame
        # Si la cámara entrega 1080p/4K (ej. canal principal 101), escalar a max_ancho
        # reduce drásticamente el uso de ancho de banda WebSocket y CPU manteniendo nitidez.
        if ancho_orig > max_ancho and max_ancho > 0:
            escala = max_ancho / float(ancho_orig)
            nuevo_ancho = max_ancho
            nuevo_alto = max(1, int(round(alto_orig * escala)))
            frame_salida = cv2.resize(
                frame, (nuevo_ancho, nuevo_alto), interpolation=cv2.INTER_AREA
            )
            alto_orig, ancho_orig = nuevo_alto, nuevo_ancho

        exito, buffer_jpg = cv2.imencode(
            ".jpg", frame_salida, [int(cv2.IMWRITE_JPEG_QUALITY), int(calidad_jpeg)]
        )
        if not exito:
            raise RuntimeError("No fue posible codificar el fotograma de la cámara en JPEG.")
        return (
            base64.b64encode(buffer_jpg.tobytes()).decode("ascii"),
            ancho_orig,
            alto_orig,
            frame_salida,
        )
    except ImportError:
        from io import BytesIO
        from PIL import Image

        # Respaldo en CPU mediante Pillow cuando cv2 no está presente (p. ej. entorno de pruebas)
        rgb = frame[:, :, ::-1] if getattr(frame, "ndim", 0) == 3 else frame
        imagen = Image.fromarray(rgb)
        if ancho_orig > max_ancho and max_ancho > 0:
            escala = max_ancho / float(ancho_orig)
            ancho_orig = max_ancho
            alto_orig = max(1, int(round(alto_orig * escala)))
            imagen = imagen.resize((ancho_orig, alto_orig))
        salida = BytesIO()
        imagen.save(salida, format="JPEG", quality=int(calidad_jpeg))
        return (
            base64.b64encode(salida.getvalue()).decode("ascii"),
            ancho_orig,
            alto_orig,
            frame,
        )


class CapturadorRTSP:
    """Gestiona el ciclo de vida de lectura continua de una cámara IP/RTSP sobre CPU.

    Implementa inyección opcional de `capture_factory` y `encoder_fn` para permitir
    pruebas unitarias deterministas sin hardware de cámara ni red real.
    """

    def __init__(
        self,
        url: str,
        capture_factory: Optional[Callable[[str], Any]] = None,
        encoder_fn: Optional[Callable[[Any, int, int], tuple[str, int, int]]] = None,
        max_ancho: int = 960,
        calidad_jpeg: int = 75,
    ) -> None:
        """Inicializa y valida la configuración del capturador RTSP.

        Args:
            url: Enlace RTSP/HTTP provisto por el usuario.
            capture_factory: Factoría opcional para instanciar el lector de video.
            encoder_fn: Función opcional para comprimir el ndarray a JPEG Base64.
            max_ancho: Ancho máximo en píxeles para transmisión eficiente en CPU.
            calidad_jpeg: Nivel de compresión JPEG [1..100].

        Raises:
            URLCamaraInvalidaError: Si el enlace no supera las reglas de seguridad.
        """
        self._url_normalizada = normalizar_url_camara(url)
        self._url_enmascarada = enmascarar_url_camara(self._url_normalizada)
        self._capture_factory = capture_factory or _crear_video_capture_opencv
        self._encoder_fn = encoder_fn or _codificar_frame_a_jpeg_b64
        self._max_ancho = max_ancho
        self._calidad_jpeg = calidad_jpeg

        self._captura: Optional[Any] = None
        self._primer_frame_pendiente: Optional[Any] = None
        self._lock = threading.Lock()
        self._activo = False
        self._ultimo_instante_fps: float = 0.0
        self._fps_suavizado: float = 0.0
        self._monitor_cpu = _MonitorRecursosCPU()

    @property
    def url_normalizada(self) -> str:
        """Devuelve la URL saneada utilizada para conectar con la cámara."""
        return self._url_normalizada

    @property
    def url_enmascarada(self) -> str:
        """Devuelve la URL segura sin exponer contraseñas para logs y UI."""
        return self._url_enmascarada

    @property
    def activo(self) -> bool:
        """Indica si el flujo de captura permanece abierto."""
        return self._activo

    def conectar(self) -> tuple[int, int]:
        """Abre la conexión hacia la cámara IP y verifica la recepción del primer cuadro.

        Returns:
            Tupla (ancho, alto) del flujo de video conectado.

        Raises:
            ConnectionError: Si la cámara rechaza la conexión, expira el timeout o no envía video.
        """
        with self._lock:
            self._liberar_interno()
            logger.info("Conectando a flujo de cámara en red: %s", self._url_enmascarada)
            captura = self._capture_factory(self._url_normalizada)

            if captura is None or not captura.isOpened():
                if captura is not None:
                    try:
                        captura.release()
                    except Exception:
                        pass
                raise ConnectionError(
                    f"No se pudo conectar con la cámara ({self._url_enmascarada}). "
                    "Verifique IP, puerto, credenciales y que esté en la misma red."
                )

            ok, frame = captura.read()
            if not ok or frame is None:
                try:
                    captura.release()
                except Exception:
                    pass
                raise ConnectionError(
                    f"La cámara ({self._url_enmascarada}) aceptó el enlace pero no entregó video. "
                    "Verifique el canal RTSP (ej. /Streaming/Channels/101) y las credenciales."
                )

            alto, ancho = int(frame.shape[0]), int(frame.shape[1])
            self._captura = captura
            self._primer_frame_pendiente = frame
            self._activo = True
            self._ultimo_instante_fps = time.perf_counter()
            self._fps_suavizado = 0.0
            return ancho, alto

    def leer_fotograma(self) -> Optional[FotogramaCapturado]:
        """Extrae, codifica y cronometra el siguiente fotograma disponible de la cámara.

        Returns:
            Instancia `FotogramaCapturado` o `None` si el flujo terminó o fue detenido.
        """
        inicio_ms = time.perf_counter()
        with self._lock:
            if not self._activo or self._captura is None:
                return None

            if self._primer_frame_pendiente is not None:
                frame = self._primer_frame_pendiente
                self._primer_frame_pendiente = None
                ok = True
            else:
                ok, frame = self._captura.read()

        if not ok or frame is None:
            return None

        codificado = self._encoder_fn(frame, self._max_ancho, self._calidad_jpeg)
        if len(codificado) >= 4:
            jpeg_b64, ancho, alto, frame_escalado = codificado[:4]
        else:
            jpeg_b64, ancho, alto = codificado
            frame_escalado = frame
        ahora = time.perf_counter()
        duracion_ms = (ahora - inicio_ms) * 1000.0

        delta_seg = ahora - self._ultimo_instante_fps
        self._ultimo_instante_fps = ahora
        if delta_seg > 0.001:
            fps_inst = 1.0 / delta_seg
            # Media móvil exponencial (alpha=0.25) para evitar saltos bruscos en el panel UI
            self._fps_suavizado = (
                fps_inst
                if self._fps_suavizado <= 0.0
                else (0.75 * self._fps_suavizado + 0.25 * fps_inst)
            )

        cpu_pct, ram_mb = self._monitor_cpu.leer_cpu_y_ram()
        return FotogramaCapturado(
            jpeg_b64=jpeg_b64,
            ancho=ancho,
            alto=alto,
            fps=round(self._fps_suavizado, 1),
            inferencia_ms=round(duracion_ms, 1),
            cpu_pct=cpu_pct,
            ram_mb=ram_mb,
            frame_bgr=frame_escalado,
        )

    def detener(self) -> None:
        """Cierra de forma segura e idempotente el descriptor OpenCV de la cámara."""
        with self._lock:
            if self._activo or self._captura is not None:
                logger.info("Liberando flujo de cámara en red: %s", self._url_enmascarada)
            self._liberar_interno()

    def _liberar_interno(self) -> None:
        """Libera recursos internos asumiendo el cerrojo adquirido."""
        self._activo = False
        self._primer_frame_pendiente = None
        if self._captura is not None:
            try:
                self._captura.release()
            except Exception as exc:
                logger.debug("Aviso al liberar VideoCapture RTSP: %s", exc)
            finally:
                self._captura = None
