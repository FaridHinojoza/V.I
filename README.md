# V.I — Sistema de Vigilancia Inteligente

Aplicacion web cliente-servidor para la deteccion de merodeo peatonal y trayectorias recurrentes mediante vision artificial y cercos virtuales dinamicos, ejecutada integramente sobre CPU y memoria RAM.

## Arquitectura
- **Estilo:** Monolito Modular Web con principios de Arquitectura Limpia (Puertos y Adaptadores ligeros), desplegado como unidad unica en Docker.
- **Backend:** Python 3.11, FastAPI, WebSockets, OpenCV, Ultralytics YOLO, ByteTrack, psutil, Bcrypt, PyJWT, PyMongo (MongoDB Atlas).
- **Frontend:** HTML5, CSS, JavaScript ES6 nativo y HTML5 Canvas (servido estaticamente por FastAPI en `/`).

## Estructura Principal
- `backend/app/core/`: configuracion, concurrencia (`ThreadPoolExecutor` + `compute_lock`), seguridad JWT/Bcrypt y telemetria `psutil`.
- `backend/app/domain/`: cerco virtual en memoria (4 a 6 vertices), trayectorias recurrentes, reglas de merodeo, alertas, metricas y puertos (`Protocol`).
- `backend/app/vision/`: estrategias ROI (`EstrategiaCercoVirtual` y `EstrategiaEscenaCompleta`), detector YOLO Singleton, fabrica ByteTrack y `MotorVisionYMerodeo`.
- `backend/app/application/`: gestion de sesion unica, evaluador experimental `.mp4` y exportador `.csv`/`.json`.
- `backend/app/infrastructure/`: repositorio MongoDB Atlas (`usuarios`, `alertas`, `evaluaciones`) y servicio SMTP.
- `backend/app/api/`: rutas REST y canal WebSocket `/ws/monitoreo`.
- `frontend/`: interfaz web de las 6 pantallas, controlador de canvas interactivo y cliente WebSocket.
- `scripts/`: inicializacion de cuenta unica en base de datos.

## Arranque Local
1. Copiar `.env.example` a `.env` y completar credenciales de MongoDB Atlas, JWT y SMTP.
2. Instalar dependencias (incluyendo PyTorch CPU-only) y ejecutar:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 1
   ```
