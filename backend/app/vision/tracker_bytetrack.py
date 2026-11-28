"""Motor de seguimiento multi-objeto ByteTrack sobre CPU y memoria RAM (US-05 / RF-08 / RNF-01).

Implementa instancias aisladas y reiniciables de ByteTrack (Zhang et al., ECCV 2022)
por sesión de monitoreo o pasada experimental:
- Filtro de Kalman lineal 8D en NumPy `[cx, cy, w, h, vx, vy, vw, vh]` sobre coordenadas
  globales normalizadas [0.0, 1.0], garantizando invariancia del `track_id` incluso cuando
  el operador arrastra los vértices del cerco virtual en caliente (RF-06).
- Asociación en cascada de dos pasadas (alta confianza y recuperación de baja confianza)
  sin requerir compiladores C++ (`lap`) ni GPU dedicada (RNF-01).
- Historial circular acotado (`deque`) de puntos de trayectoria para proteger la RAM.
"""

from __future__ import annotations

from collections import deque
import math
from typing import Deque, List, Sequence, Tuple

import numpy as np

from backend.app.domain.ports import DeteccionPeaton

_CLASE_PERSONA_COCO: int = 0


def calcular_iou_normalizado(
    caja_a: Tuple[float, float, float, float],
    caja_b: Tuple[float, float, float, float],
) -> float:
    """Calcula la Intersección sobre Unión (IoU) entre dos cajas `(x1, y1, x2, y2)`.

    Args:
        caja_a: Límites `(x1, y1, x2, y2)` de la primera caja.
        caja_b: Límites `(x1, y1, x2, y2)` de la segunda caja.

    Returns:
        Valor flotante de IoU en el rango [0.0, 1.0].
    """
    ix1 = max(caja_a[0], caja_b[0])
    iy1 = max(caja_a[1], caja_b[1])
    ix2 = min(caja_a[2], caja_b[2])
    iy2 = min(caja_a[3], caja_b[3])

    inter_w = max(0.0, ix2 - ix1)
    inter_h = max(0.0, iy2 - iy1)
    area_inter = inter_w * inter_h
    if area_inter <= 0.0:
        return 0.0

    area_a = max(1e-9, (caja_a[2] - caja_a[0]) * (caja_a[3] - caja_a[1]))
    area_b = max(1e-9, (caja_b[2] - caja_b[0]) * (caja_b[3] - caja_b[1]))
    union = area_a + area_b - area_inter
    return float(area_inter / max(1e-9, union))


def _afinidad_espacial(
    caja_pred: Tuple[float, float, float, float],
    caja_det: Tuple[float, float, float, float],
) -> float:
    """Combina IoU con proximidad de centroide para tolerar cadencias bajas en CPU (~4-5 Hz).

    Por qué: Cuando la cámara web local envía cuadros cada ~220 ms para no saturar la CPU,
    un peatón caminando rápido puede desplazarse más de medio ancho corporal entre muestras,
    reduciendo el IoU puro. Combinar IoU con una compuerta gaussiana corta de escala relativa
    preserva la continuidad del `track_id` sin mezclar personas distantes.
    """
    iou = calcular_iou_normalizado(caja_pred, caja_det)
    pw = max(0.01, caja_pred[2] - caja_pred[0])
    ph = max(0.01, caja_pred[3] - caja_pred[1])
    dw = max(0.01, caja_det[2] - caja_det[0])
    dh = max(0.01, caja_det[3] - caja_det[1])

    pcx = (caja_pred[0] + caja_pred[2]) * 0.5
    pcy = (caja_pred[1] + caja_pred[3]) * 0.5
    dcx = (caja_det[0] + caja_det[2]) * 0.5
    dcy = (caja_det[1] + caja_det[3]) * 0.5

    escala_ref = max(0.02, (max(pw, dw) + max(ph, dh)) * 0.5)
    dist_norm = math.hypot(pcx - dcx, pcy - dcy) / escala_ref

    # Rechazar candidatos con tamaño radicalmente incompatible o demasiado lejanos
    razon_altura = min(ph, dh) / max(ph, dh)
    if razon_altura < 0.40 or dist_norm > 1.35:
        return iou

    bono_cercania = max(0.0, 1.0 - (dist_norm / 1.35)) * 0.35 * razon_altura
    return min(1.0, max(iou, iou * 0.75 + bono_cercania))


def _emparejar_bipartito_codicioso(
    cajas_pistas: Sequence[Tuple[float, float, float, float]],
    cajas_dets: Sequence[Tuple[float, float, float, float]],
    umbral_min: float,
    solo_iou_estricto: bool = False,
) -> Tuple[List[Tuple[int, int]], List[int], List[int]]:
    """Resuelve la asignación 1-a-1 entre pistas y detecciones maximizando afinidad/IoU.

    Args:
        cajas_pistas: Cajas predichas por el filtro de Kalman para las pistas candidatas.
        cajas_dets: Cajas observadas por YOLO en el fotograma actual.
        umbral_min: Puntaje mínimo de afinidad/IoU para aceptar un emparejamiento.
        solo_iou_estricto: Si es True (2.ª pasada baja confianza), exige IoU geométrico puro.

    Returns:
        Tupla `(pares_emparejados, idx_pistas_libres, idx_dets_libres)`.
    """
    num_pistas = len(cajas_pistas)
    num_dets = len(cajas_dets)
    if num_pistas == 0 or num_dets == 0:
        return [], list(range(num_pistas)), list(range(num_dets))

    candidatos: List[Tuple[float, int, int]] = []
    for idx_p, cp in enumerate(cajas_pistas):
        for idx_d, cd in enumerate(cajas_dets):
            puntaje = (
                calcular_iou_normalizado(cp, cd)
                if solo_iou_estricto
                else _afinidad_espacial(cp, cd)
            )
            if puntaje >= umbral_min:
                candidatos.append((puntaje, idx_p, idx_d))

    # Orden descendente determinista por afinidad para asignar primero los pares más seguros
    candidatos.sort(key=lambda item: item[0], reverse=True)

    pistas_usadas: set[int] = set()
    dets_usadas: set[int] = set()
    emparejados: List[Tuple[int, int]] = []

    for _, idx_p, idx_d in candidatos:
        if idx_p in pistas_usadas or idx_d in dets_usadas:
            continue
        pistas_usadas.add(idx_p)
        dets_usadas.add(idx_d)
        emparejados.append((idx_p, idx_d))

    pistas_libres = [i for i in range(num_pistas) if i not in pistas_usadas]
    dets_libres = [j for j in range(num_dets) if j not in dets_usadas]
    return emparejados, pistas_libres, dets_libres


class _FiltroKalmanCaja2D:
    """Filtro de Kalman de velocidad constante en espacio normalizado `[cx, cy, w, h]`."""

    _MATRIZ_F = np.eye(8, dtype=np.float64)
    for _i in range(4):
        _MATRIZ_F[_i, _i + 4] = 1.0

    _MATRIZ_H = np.eye(4, 8, dtype=np.float64)

    def __init__(self, x1: float, y1: float, x2: float, y2: float) -> None:
        cx = (x1 + x2) * 0.5
        cy = (y1 + y2) * 0.5
        w = max(0.005, x2 - x1)
        h = max(0.005, y2 - y1)

        self.estado = np.array([cx, cy, w, h, 0.0, 0.0, 0.0, 0.0], dtype=np.float64)
        self.covarianza = np.diag(
            [1e-3, 1e-3, 1e-3, 1e-3, 1e-2, 1e-2, 5e-3, 5e-3]
        ).astype(np.float64)
        self._ruido_q = np.diag(
            [4e-4, 4e-4, 2e-4, 2e-4, 2e-3, 2e-3, 5e-4, 5e-4]
        ).astype(np.float64)
        self._ruido_r = np.diag([5e-4, 5e-4, 8e-4, 8e-4]).astype(np.float64)

    def predecir(self) -> Tuple[float, float, float, float]:
        """Avanza un paso temporal el estado cinemático y retorna la caja predicha."""
        self.estado = self._MATRIZ_F @ self.estado
        self.estado[2] = max(0.005, float(self.estado[2]))
        self.estado[3] = max(0.005, float(self.estado[3]))
        self.covarianza = (
            self._MATRIZ_F @ self.covarianza @ self._MATRIZ_F.T + self._ruido_q
        )
        return self.obtener_caja_xyxy()

    def corregir(self, x1: float, y1: float, x2: float, y2: float) -> None:
        """Actualiza el estado estimado con una nueva medición observada por YOLO."""
        medicion = np.array(
            [
                (x1 + x2) * 0.5,
                (y1 + y2) * 0.5,
                max(0.005, x2 - x1),
                max(0.005, y2 - y1),
            ],
            dtype=np.float64,
        )
        innovacion = medicion - (self._MATRIZ_H @ self.estado)
        cov_innov = self._MATRIZ_H @ self.covarianza @ self._MATRIZ_H.T + self._ruido_r
        ganancia_k = self.covarianza @ self._MATRIZ_H.T @ np.linalg.inv(cov_innov)

        self.estado = self.estado + (ganancia_k @ innovacion)
        self.estado[2] = max(0.005, float(self.estado[2]))
        self.estado[3] = max(0.005, float(self.estado[3]))
        identidad = np.eye(8, dtype=np.float64)
        self.covarianza = (identidad - ganancia_k @ self._MATRIZ_H) @ self.covarianza

    def obtener_caja_xyxy(self) -> Tuple[float, float, float, float]:
        """Convierte el vector `[cx, cy, w, h]` a límites acotados `(x1, y1, x2, y2)`."""
        cx, cy, w, h = (
            float(self.estado[0]),
            float(self.estado[1]),
            float(self.estado[2]),
            float(self.estado[3]),
        )
        x1 = max(0.0, min(1.0, cx - w * 0.5))
        y1 = max(0.0, min(1.0, cy - h * 0.5))
        x2 = max(x1 + 1e-4, min(1.0, cx + w * 0.5))
        y2 = max(y1 + 1e-4, min(1.0, cy + h * 0.5))
        return (x1, y1, x2, y2)


class _PistaRastreada:
    """Estado interno en memoria de un peatón seguido por ByteTrack."""

    def __init__(
        self,
        track_id: int,
        deteccion: DeteccionPeaton,
        max_historial: int,
    ) -> None:
        self.track_id = int(track_id)
        self.kalman = _FiltroKalmanCaja2D(
            deteccion.x1, deteccion.y1, deteccion.x2, deteccion.y2
        )
        self.confianza = float(deteccion.confianza)
        self.caja_actual: Tuple[float, float, float, float] = (
            deteccion.x1,
            deteccion.y1,
            deteccion.x2,
            deteccion.y2,
        )
        self.frames_perdidos: int = 0
        self.trayectoria: Deque[Tuple[float, float]] = deque(maxlen=max_historial)
        self.trayectoria.append(deteccion.punto_pies)

    def registrar_observacion(self, det: DeteccionPeaton) -> None:
        """Incorpora una detección asociada manteniendo suavidad cinemática."""
        self.kalman.corregir(det.x1, det.y1, det.x2, det.y2)
        self.caja_actual = (det.x1, det.y1, det.x2, det.y2)
        self.confianza = float(det.confianza)
        self.frames_perdidos = 0
        self.trayectoria.append(det.punto_pies)

    def a_deteccion_peaton(self) -> DeteccionPeaton:
        """Exporta el estado actual de la pista como Value Object inmutable de dominio."""
        x1, y1, x2, y2 = self.caja_actual
        return DeteccionPeaton(
            x1=round(x1, 6),
            y1=round(y1, 6),
            x2=round(x2, 6),
            y2=round(y2, 6),
            confianza=round(self.confianza, 4),
            clase_id=_CLASE_PERSONA_COCO,
            track_id=self.track_id,
            trayectoria=tuple(self.trayectoria),
        )


class RastreadorByteTrack:
    """Rastreador ByteTrack aislado por sesión o evaluación experimental sobre CPU (US-05).

    Ejecuta asociación en dos etapas:
    1. Empareja pistas activas y recientemente perdidas con detecciones de alta confianza.
    2. Recupera pistas activas no emparejadas usando detecciones de baja confianza (oclusiones).
    """

    def __init__(
        self,
        conf_alta: float = 0.35,
        conf_baja: float = 0.15,
        umbral_afinidad_alta: float = 0.22,
        umbral_iou_baja: float = 0.20,
        max_frames_perdidos: int = 25,
        max_puntos_trayectoria: int = 30,
    ) -> None:
        """Configura una instancia limpia de seguimiento ByteTrack en memoria RAM.

        Args:
            conf_alta: Umbral de confianza para detecciones primarias e inicio de pistas.
            conf_baja: Umbral inferior para la 2.ª pasada de recuperación ByteTrack.
            umbral_afinidad_alta: Afinidad mínima requerida en la 1.ª pasada.
            umbral_iou_baja: IoU mínimo estricto requerido en la 2.ª pasada.
            max_frames_perdidos: Ciclos máximos que se retiene una pista ocluida (`track_buffer`).
            max_puntos_trayectoria: Longitud máxima de la estela `punto_pies` por persona.
        """
        self._conf_alta = max(0.10, min(0.95, float(conf_alta)))
        self._conf_baja = max(0.05, min(self._conf_alta, float(conf_baja)))
        self._umbral_alta = max(0.05, min(0.90, float(umbral_afinidad_alta)))
        self._umbral_baja = max(0.05, min(0.90, float(umbral_iou_baja)))
        self._max_perdidos = max(1, int(max_frames_perdidos))
        self._max_historial = max(2, int(max_puntos_trayectoria))

        self._siguiente_id: int = 1
        self._pistas: List[_PistaRastreada] = []

    @property
    def conf_baja(self) -> float:
        """Retorna el umbral inferior requerido al detector YOLO para la 2.ª pasada."""
        return self._conf_baja

    @property
    def pistas_en_memoria(self) -> int:
        """Cantidad total de pistas (activas + en búfer de oclusión) retenidas en RAM."""
        return len(self._pistas)

    def reiniciar(self) -> None:
        """Purga todas las pistas activas y restablece el contador de IDs en la sesión."""
        self._pistas.clear()
        self._siguiente_id = 1

    def actualizar(
        self,
        detecciones: Sequence[DeteccionPeaton],
    ) -> Tuple[DeteccionPeaton, ...]:
        """Ejecuta un ciclo completo de predicción Kalman y asociación ByteTrack en 2 pasadas.

        Args:
            detecciones: Candidatos de clase persona en coordenadas globales [0.0, 1.0].

        Returns:
            Tupla de `DeteccionPeaton` visibles en el cuadro actual con `track_id` y `trayectoria`.
        """
        dets_altas: List[DeteccionPeaton] = []
        dets_bajas: List[DeteccionPeaton] = []
        for det in detecciones:
            if int(det.clase_id) != _CLASE_PERSONA_COCO:
                continue
            if det.confianza >= self._conf_alta:
                dets_altas.append(det)
            elif det.confianza >= self._conf_baja:
                dets_bajas.append(det)

        # 1. Predecir posición cinemática para todas las pistas conocidas
        cajas_predichas = [pista.kalman.predecir() for pista in self._pistas]

        # 2. Primera pasada: asociar pistas (activas y perdidas) con detecciones altas
        cajas_altas = [(d.x1, d.y1, d.x2, d.y2) for d in dets_altas]
        pares_1, pistas_restantes_1, dets_altas_libres = _emparejar_bipartito_codicioso(
            cajas_predichas,
            cajas_altas,
            umbral_min=self._umbral_alta,
            solo_iou_estricto=False,
        )

        for idx_pista, idx_det in pares_1:
            self._pistas[idx_pista].registrar_observacion(dets_altas[idx_det])

        # 3. Segunda pasada ByteTrack: recuperar pistas activas usando detecciones débiles
        idx_activas_restantes = [
            idx for idx in pistas_restantes_1 if self._pistas[idx].frames_perdidos <= 1
        ]
        idx_perdidas_previas = [
            idx for idx in pistas_restantes_1 if self._pistas[idx].frames_perdidos > 1
        ]

        cajas_pred_activas = [cajas_predichas[idx] for idx in idx_activas_restantes]
        cajas_bajas = [(d.x1, d.y1, d.x2, d.y2) for d in dets_bajas]
        pares_2, sub_sin_emparejar, _ = _emparejar_bipartito_codicioso(
            cajas_pred_activas,
            cajas_bajas,
            umbral_min=self._umbral_baja,
            solo_iou_estricto=True,
        )

        for sub_idx_pista, idx_det_baja in pares_2:
            pista_real = self._pistas[idx_activas_restantes[sub_idx_pista]]
            pista_real.registrar_observacion(dets_bajas[idx_det_baja])

        # 4. Marcar pistas no observadas en este ciclo y purgar las que superen track_buffer
        no_observadas = [idx_activas_restantes[i] for i in sub_sin_emparejar] + idx_perdidas_previas
        for idx_no_obs in no_observadas:
            self._pistas[idx_no_obs].frames_perdidos += 1

        self._pistas = [
            p for p in self._pistas if p.frames_perdidos <= self._max_perdidos
        ]

        # 5. Inicializar nuevas pistas únicamente a partir de detecciones altas no asignadas
        for idx_nueva in dets_altas_libres:
            nueva_pista = _PistaRastreada(
                track_id=self._siguiente_id,
                deteccion=dets_altas[idx_nueva],
                max_historial=self._max_historial,
            )
            self._siguiente_id += 1
            self._pistas.append(nueva_pista)

        # Retornar en orden estable por track_id solo los peatones visibles en este cuadro
        visibles = [p for p in self._pistas if p.frames_perdidos == 0]
        visibles.sort(key=lambda p: p.track_id)
        return tuple(p.a_deteccion_peaton() for p in visibles)
