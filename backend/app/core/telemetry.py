"""Monitor de telemetría operativa de las 8 métricas computacionales (RF-11 / US-05 / V 1.2).

Calcula sin bloquear el lazo asíncrono:
1. Velocidad de procesamiento (FPS) con media móvil exponencial.
2. Tiempo de inferencia (ms) suministrado por el pipeline detector + rastreador.
3. Porcentaje de área del cerco (%).
4. Uso de procesador (% CPU) normalizado por núcleos lógicos mediante `psutil`.
5. Consumo de memoria residente (MB RAM) del servidor mediante `psutil`.
6. Uso de GPU (% GPU) con sonda oportunista sin dependencias CUDA (0.0 % en CPU-only RNF-01).
7. Ancho de banda (KB/s) sobre una ventana deslizante del payload real cliente-servidor.
8. Conteo de peatones rastreados y alertas confirmadas.
"""

from __future__ import annotations

from collections import deque
import os
import shutil
import subprocess
import threading
import time
from typing import Any, Callable, Deque, Optional, Tuple

from backend.app.domain.metricas import MetricasOperativas

_VENTANA_BANDA_SEG: float = 2.0
_CACHE_GPU_SEG: float = 2.5
_ALPHA_EMA_FPS: float = 0.25


class _SondaGPUOpcional:
    """Consulta no obligatoria de utilización de GPU respetando estrictamente RNF-01.

    Por qué: Requisitos_Sistema_VI V 1.2 incorpora `% GPU` dentro de las 8 métricas
    computacionales manteniendo RNF-01 (ejecución 100 % sobre CPU y RAM sin librerías CUDA).
    Si el servidor dispone de `nvidia-smi` en PATH lo consulta con caché; en contenedores
    puramente CPU retorna determinísticamente `0.0 %` sin penalizar latencia.
    """

    def __init__(self, lector_externo: Optional[Callable[[], float]] = None) -> None:
        self._lector_externo = lector_externo
        self._ruta_smi: Optional[str] = (
            None if lector_externo is not None else shutil.which("nvidia-smi")
        )
        self._ultimo_valor: float = 0.0
        self._ultimo_muestreo: float = 0.0
        self._lock = threading.Lock()

    def leer_porcentaje(self) -> float:
        """Obtiene el porcentaje de utilización de GPU en [0.0, 100.0]."""
        if self._lector_externo is not None:
            try:
                return min(100.0, max(0.0, float(self._lector_externo())))
            except Exception:
                return 0.0

        if not self._ruta_smi:
            return 0.0

        ahora = time.monotonic()
        with self._lock:
            if (ahora - self._ultimo_muestreo) < _CACHE_GPU_SEG:
                return self._ultimo_valor

            self._ultimo_muestreo = ahora
            try:
                salida = subprocess.check_output(
                    [
                        self._ruta_smi,
                        "--query-gpu=utilization.gpu",
                        "--format=csv,noheader,nounits",
                    ],
                    timeout=0.35,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                primera_linea = salida.strip().splitlines()[0].strip()
                self._ultimo_valor = min(100.0, max(0.0, float(primera_linea)))
            except Exception:
                # Si falla o no existe dispositivo accesible, desactivar reintentos costosos
                self._ruta_smi = None
                self._ultimo_valor = 0.0
            return self._ultimo_valor


class MonitorTelemetriaProceso:
    """Recolector thread-safe de recursos de proceso, FPS y ancho de banda por sesión."""

    def __init__(
        self,
        ventana_banda_seg: float = _VENTANA_BANDA_SEG,
        lector_gpu: Optional[Callable[[], float]] = None,
    ) -> None:
        """Inicializa el monitor de telemetría para una sesión de vigilancia o evaluación.

        Args:
            ventana_banda_seg: Duración en segundos de la ventana móvil para calcular KB/s.
            lector_gpu: Función inyectable opcional para pruebas unitarias de `% GPU`.
        """
        self._ventana_seg = max(0.25, float(ventana_banda_seg))
        self._num_nucleos = max(1, os.cpu_count() or 1)
        self._proceso: Optional[Any] = None
        self._sonda_gpu = _SondaGPUOpcional(lector_externo=lector_gpu)

        try:
            import psutil

            self._proceso = psutil.Process(os.getpid())
            # Llamada inicial no bloqueante para establecer la línea base del contador CPU
            self._proceso.cpu_percent(interval=None)
        except Exception:
            self._proceso = None

        self._lock = threading.Lock()
        self._ultimo_frame_ts: float = 0.0
        self._fps_suavizado: float = 0.0
        self._inicio_ventana_banda: float = 0.0
        self._eventos_bytes: Deque[Tuple[float, int]] = deque()

    def reiniciar(self) -> None:
        """Restablece los acumuladores temporales de FPS y ancho de banda de la sesión."""
        with self._lock:
            self._ultimo_frame_ts = 0.0
            self._fps_suavizado = 0.0
            self._inicio_ventana_banda = 0.0
            self._eventos_bytes.clear()

    def registrar_fotograma(self, timestamp: Optional[float] = None) -> float:
        """Registra la finalización de un fotograma y actualiza los FPS suavizados.

        Args:
            timestamp: Marca monótona opcional (para pruebas deterministas).

        Returns:
            Velocidad actual suavizada en cuadros por segundo.
        """
        ahora = time.perf_counter() if timestamp is None else float(timestamp)
        with self._lock:
            if self._ultimo_frame_ts > 0.0:
                delta = ahora - self._ultimo_frame_ts
                if delta > 0.0005:
                    fps_inst = 1.0 / delta
                    self._fps_suavizado = (
                        fps_inst
                        if self._fps_suavizado <= 0.0
                        else (
                            (1.0 - _ALPHA_EMA_FPS) * self._fps_suavizado
                            + _ALPHA_EMA_FPS * fps_inst
                        )
                    )
            self._ultimo_frame_ts = ahora
            return round(self._fps_suavizado, 1)

    def registrar_bytes_payload(
        self, num_bytes: int, timestamp: Optional[float] = None
    ) -> float:
        """Acumula bytes de carga útil transmitidos o recibidos y calcula KB/s actuales.

        Args:
            num_bytes: Tamaño en bytes del mensaje JSON o fotograma Base64.
            timestamp: Marca monótona opcional.

        Returns:
            Tasa de transferencia actual en kilobytes por segundo (KB/s).
        """
        if num_bytes <= 0:
            return self.calcular_ancho_banda_kbs(timestamp=timestamp)

        ahora = time.perf_counter() if timestamp is None else float(timestamp)
        with self._lock:
            if self._inicio_ventana_banda <= 0.0:
                self._inicio_ventana_banda = ahora
            self._eventos_bytes.append((ahora, int(num_bytes)))
            self._purgar_ventana_antigua(ahora)
            return self._calcular_kbs_interno(ahora)

    def calcular_ancho_banda_kbs(self, timestamp: Optional[float] = None) -> float:
        """Consulta la tasa actual de transferencia en KB/s limpiando muestras expiradas."""
        ahora = time.perf_counter() if timestamp is None else float(timestamp)
        with self._lock:
            self._purgar_ventana_antigua(ahora)
            return self._calcular_kbs_interno(ahora)

    def leer_cpu_ram_gpu(self) -> Tuple[float, float, float]:
        """Mide de forma no bloqueante (% CPU, MB RAM, % GPU) del servidor.

        Returns:
            Tupla `(cpu_pct, ram_mb, gpu_pct)`.
        """
        cpu_pct = 0.0
        ram_mb = 0.0
        if self._proceso is not None:
            try:
                cpu_raw = float(self._proceso.cpu_percent(interval=None))
                cpu_pct = round(min(100.0, max(0.0, cpu_raw / self._num_nucleos)), 1)
                ram_bytes = float(self._proceso.memory_info().rss)
                ram_mb = round(ram_bytes / (1024.0 * 1024.0), 1)
            except Exception:
                cpu_pct, ram_mb = 0.0, 0.0

        gpu_pct = round(self._sonda_gpu.leer_porcentaje(), 1)
        return cpu_pct, ram_mb, gpu_pct

    def construir_metricas(
        self,
        *,
        inferencia_ms: float = 0.0,
        area_cerco_pct: float = 0.0,
        peatones: int = 0,
        alertas: int = 0,
        fps_override: Optional[float] = None,
    ) -> MetricasOperativas:
        """Consolida un corte instantáneo completo con las 8 métricas computacionales.

        Args:
            inferencia_ms: Tiempo de ejecución de detector + rastreador en milisegundos.
            area_cerco_pct: Porcentaje de área del cerco activo [0..100].
            peatones: Peatones rastreados dentro del polígono.
            alertas: Alertas confirmadas en la sesión.
            fps_override: Si se indica, usa este FPS en lugar del contador interno.

        Returns:
            Objeto inmutable `MetricasOperativas` listo para serialización JSON.
        """
        cpu_pct, ram_mb, gpu_pct = self.leer_cpu_ram_gpu()
        kbs = self.calcular_ancho_banda_kbs()
        with self._lock:
            fps_actual = (
                float(fps_override) if fps_override is not None else self._fps_suavizado
            )

        return MetricasOperativas(
            fps=fps_actual,
            inferencia_ms=inferencia_ms,
            area_cerco_pct=area_cerco_pct,
            cpu_pct=cpu_pct,
            ram_mb=ram_mb,
            gpu_pct=gpu_pct,
            ancho_banda_kbs=kbs,
            peatones=peatones,
            alertas=alertas,
        )

    def _purgar_ventana_antigua(self, ahora: float) -> None:
        """Descarta muestras de red fuera de la ventana deslizante asumiendo lock activo."""
        limite = ahora - self._ventana_seg
        while self._eventos_bytes and self._eventos_bytes[0][0] < limite:
            self._eventos_bytes.popleft()

    def _calcular_kbs_interno(self, ahora: float) -> float:
        """Calcula KB/s efectivos evitando subestimar durante el primer segundo de arranque."""
        if not self._eventos_bytes:
            return 0.0
        total_bytes = sum(tam for _, tam in self._eventos_bytes)
        transcurrido = max(0.20, min(self._ventana_seg, ahora - self._inicio_ventana_banda))
        return round((total_bytes / 1024.0) / transcurrido, 1)
