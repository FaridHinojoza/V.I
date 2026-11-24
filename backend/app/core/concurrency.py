"""Gestión de concurrencia en CPU: ThreadPoolExecutor dedicado de visión y compute_lock.

Garantiza que las operaciones intensivas de recorte espacial y detección YOLO sobre CPU
y memoria RAM (RNF-01) no bloqueen el bucle de eventos asíncrono de FastAPI/WebSockets.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import functools
import threading
from typing import Any, Callable, TypeVar

T = TypeVar("T")

# Lock de sincronización para proteger la instancia Singleton del modelo YOLO en CPU/RAM
compute_lock = threading.Lock()

# Pool dedicado de 2 hilos de trabajo (alineado con la especificación RNF-01 de mínimo 2 núcleos CPU)
_vision_cpu_executor = ThreadPoolExecutor(
    max_workers=2,
    thread_name_prefix="vi_yolo_cpu",
)


async def ejecutar_inferencia_cpu(func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Ejecuta una función síncrona de visión artificial en el ThreadPoolExecutor de CPU.

    Args:
        func: Función o método síncrono de procesamiento espacial / inferencia YOLO.
        *args: Argumentos posicionales para la función.
        **kwargs: Argumentos con nombre para la función.

    Returns:
        El resultado retornado por `func(*args, **kwargs)`.
    """
    loop = asyncio.get_running_loop()
    tarea = functools.partial(func, *args, **kwargs)
    return await loop.run_in_executor(_vision_cpu_executor, tarea)
