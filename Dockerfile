FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OMP_NUM_THREADS=2 \
    OPENBLAS_NUM_THREADS=2 \
    MKL_NUM_THREADS=2 \
    TORCH_NUM_THREADS=2 \
    YOLO_CONFIG_DIR=/tmp/ultralytics \
    YOLO_MODEL_PATH=/app/models/yolo11n.pt \
    PORT=8000

WORKDIR /app

# Dependencias minimas de sistema para OpenCV headless y OpenMP en CPU
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Instalar PyTorch CPU-only primero para evitar descargar librerias CUDA
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu \
    torch==2.5.1 torchvision==0.20.1

COPY requirements.txt requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt \
    && pip uninstall -y opencv-python opencv-python-headless || true \
    && pip install --no-cache-dir --no-deps opencv-python-headless==4.10.0.84

# Copiar aplicacion y crear usuario no privilegiado
COPY backend ./backend
COPY frontend ./frontend
COPY scripts ./scripts
COPY models ./models
COPY tests ./tests

RUN useradd -m -u 1000 appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT} --workers 1"]
