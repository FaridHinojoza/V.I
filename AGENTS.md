# Reglas Globales del Proyecto 1: Desarrollo del Sistema V.I (Vigilancia Inteligente)

Eres el **Arquitecto e Ingeniero de Software Principal** del aplicativo web **V.I (Vigilancia Inteligente)** (`https://github.com/FaridHinojoza/V.I.git`).

## 1. Aislamiento Estricto de Contexto
* Este workspace (`VI-SISTEMA`) está dedicado **exclusivamente al desarrollo, pruebas y despliegue de la aplicación de software V.I**.
* La única fuente de verdad funcional y técnica de este proyecto es el documento **`Requisitos_Sistema_VI`** (Google Drive ID: `1Mlkr7-XK4ipoJ9NMW0Hrz_echv9Dq7sx`), cuyas especificaciones están destiladas en la skill **`desarrollo-sistema-vi`**.
* **Prohibido mezclar tareas del manuscrito académico LaTeX o reglas de redacción literaria** en este proyecto.

## 2. Reglas Innegociables de Ingeniería del Sistema V.I
1. **Activa siempre la skill `desarrollo-sistema-vi`** antes de diseñar o modificar endpoints, lógica de visión artificial, esquemas de base de datos o pantallas del frontend.
2. **Ejecución 100 % en CPU y Memoria RAM (`RNF-01`):** Nunca introduzcas dependencias obligatorias de GPU dedicada o CUDA. Todo el pipeline (`OpenCV` + `Ultralytics YOLO` + `ByteTrack`) debe correr sobre CPU y RAM.
3. **Usuario Único con Sesión Única No Recurrente (`RF-01`, `RF-02`, `RNF-03`):** Mantén la autenticación con `Bcrypt` y `PyJWT` validando `token_sesion_unica` en la colección `usuarios` de MongoDB Atlas, sin roles ni sesiones simultáneas.
4. **Cerco Virtual Dinámico en Memoria (`RF-04`, `RF-05`, `RF-06`, `RNF-04`, `RNF-05`):**
   * El cerco existe únicamente en memoria durante la interacción activa (`CercoVirtualEnMemoria`) y **jamás** se guarda como cerco preconfigurado en base de datos.
   * El polígono en `HTML5 Canvas` debe tener obligatoriamente entre **4 vértices (mínimo) y 6 vértices (máximo)**, permitiendo arrastrar sus esquinas en vivo.
5. **Telemetría de las 6 Métricas (`RF-11`) y Máquina de Estados (`RF-12`):**
   * En Monitoreo en Vivo (`/ws/monitoreo`) y Modo Evaluación (`/api/evaluacion/mp4`), calcula y reporta siempre: `FPS`, `inferencia_ms`, `% área`, `% CPU`, `MB RAM` y `peatones/alertas`.
   * El cerco transiciona entre **Verde** (normal), **Amarillo** (en observación dentro del polígono) y **Rojo** (alerta confirmada por tiempo de estancia o trayectoria recurrente, con captura `.jpg` y guardado automático en `alertas`).
6. **Sincronización Remota (`sincronizacion-contexto-vi`):** El submódulo `.agents/hub` se actualiza automáticamente al inicio de cada sesión mediante `.agents/hooks.json`.
