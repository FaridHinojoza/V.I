"""Configuración centralizada del sistema V.I cargada desde variables de entorno."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

_DEFAULT_ENV_PATH = Path(__file__).resolve().parent.parent.parent.parent / ".env"
_PLACEHOLDER_JWT_SECRETS = frozenset(
    {
        "CAMBIAR_POR_SECRETO_ALEATORIO_SEGURO_MIN_32_CHARS",
        "cambiar_por_secreto_seguro_vi_2026",
        "<secure-random-secret>",
    }
)


def _strip_inline_comment(raw: str) -> str:
    """Elimina comentarios '#' en línea preservando literales entrecomillados."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return raw[:idx].rstrip()
    return raw.strip()


def load_dotenv_file(env_path: Optional[Path] = None) -> None:
    """Carga pares clave=valor desde .env sin sobreescribir variables de entorno existentes."""
    target = env_path if env_path is not None else _DEFAULT_ENV_PATH
    if not target.is_file():
        return

    for raw_line in target.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, raw_value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = _strip_inline_comment(raw_value.strip())
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]

        os.environ.setdefault(key, value)


def _parse_int(name: str, default: int, min_val: int, max_val: int) -> int:
    """Valida y parsea una variable de entorno entera dentro de un rango permitido."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        parsed = int(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"La variable de entorno '{name}' debe ser un entero válido, se recibió: {raw!r}"
        ) from exc
    if not (min_val <= parsed <= max_val):
        raise ValueError(
            f"La variable de entorno '{name}' debe estar entre {min_val} y {max_val}, se recibió: {parsed}"
        )
    return parsed


def _parse_float(name: str, default: float, min_val: float, max_val: float) -> float:
    """Valida y parsea una variable de entorno decimal dentro de un rango permitido."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        parsed = float(raw.strip())
    except ValueError as exc:
        raise ValueError(
            f"La variable de entorno '{name}' debe ser un número real válido, se recibió: {raw!r}"
        ) from exc
    if not (min_val <= parsed <= max_val):
        raise ValueError(
            f"La variable de entorno '{name}' debe estar entre {min_val} y {max_val}, se recibió: {parsed}"
        )
    return parsed


@dataclass(frozen=True)
class Settings:
    """Ajustes de configuración fuertemente tipados para el Sistema V.I."""

    mongo_uri: str
    mongo_db_name: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_expiration_minutes: int
    default_username: str
    default_email: str
    default_password: str
    bcrypt_rounds: int
    smtp_host: str
    smtp_port: int
    smtp_user: str
    smtp_password: str
    smtp_from: str
    app_port: int
    log_level: str
    yolo_model_path: str = "models/yolo11n.pt"
    yolo_conf_threshold: float = 0.35
    yolo_imgsz_max: int = 640
    roi_padding_pct: float = 0.15

    @property
    def MONGO_URI(self) -> str:
        return self.mongo_uri

    @property
    def MONGO_DB_NAME(self) -> str:
        return self.mongo_db_name

    @property
    def JWT_SECRET(self) -> str:
        return self.jwt_secret

    @property
    def JWT_ALGORITHM(self) -> str:
        return self.jwt_algorithm

    @property
    def JWT_EXPIRATION_MINUTES(self) -> int:
        return self.jwt_expiration_minutes

    @property
    def DEFAULT_USERNAME(self) -> str:
        return self.default_username

    @property
    def DEFAULT_EMAIL(self) -> str:
        return self.default_email

    @property
    def DEFAULT_PASSWORD(self) -> str:
        return self.default_password

    @property
    def BCRYPT_ROUNDS(self) -> int:
        return self.bcrypt_rounds

    @property
    def SMTP_HOST(self) -> str:
        return self.smtp_host

    @property
    def SMTP_PORT(self) -> int:
        return self.smtp_port

    @property
    def SMTP_USER(self) -> str:
        return self.smtp_user

    @property
    def SMTP_PASSWORD(self) -> str:
        return self.smtp_password

    @property
    def SMTP_FROM(self) -> str:
        return self.smtp_from

    @property
    def APP_PORT(self) -> int:
        return self.app_port

    @property
    def LOG_LEVEL(self) -> str:
        return self.log_level

    @property
    def YOLO_MODEL_PATH(self) -> str:
        return self.yolo_model_path

    @property
    def YOLO_CONF_THRESHOLD(self) -> float:
        return self.yolo_conf_threshold

    @property
    def YOLO_IMGSZ_MAX(self) -> int:
        return self.yolo_imgsz_max

    @property
    def ROI_PADDING_PCT(self) -> float:
        return self.roi_padding_pct

    def validate_jwt_secret(self) -> None:
        """Asegura que JWT_SECRET esté presente y tenga longitud segura mínima de 32 caracteres."""
        secret = self.jwt_secret.strip()
        if not secret or secret in _PLACEHOLDER_JWT_SECRETS or len(secret) < 32:
            raise ValueError(
                "JWT_SECRET debe configurarse con un secreto criptográfico de al menos 32 caracteres."
            )

    @classmethod
    def from_env(cls, env_path: Optional[Path] = None) -> Settings:
        """Construye una instancia de Settings a partir de variables de entorno y archivo .env."""
        return get_settings(env_path=env_path)


Config = Settings


def get_settings(env_path: Optional[Path] = None) -> Settings:
    """Carga la configuración del sistema desde el entorno o archivo .env."""
    load_dotenv_file(env_path)

    jwt_secret = os.getenv("JWT_SECRET") or os.getenv("JWT_SECRET_KEY") or ""
    mongo_uri = os.getenv("MONGO_URI") or "mongodb://mongodb:27017"
    mongo_db_name = os.getenv("MONGO_DB_NAME") or "vi_db"
    jwt_algorithm = os.getenv("JWT_ALGORITHM") or "HS256"
    default_username = os.getenv("DEFAULT_USERNAME") or "vi"
    default_email = os.getenv("DEFAULT_EMAIL") or "dsceli@espe.edu.ec"
    default_password = os.getenv("DEFAULT_PASSWORD") or "OperadorVI2026*"
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_from = os.getenv("SMTP_FROM") or "no-reply@espe.edu.ec"
    log_level = (os.getenv("LOG_LEVEL") or "INFO").upper()
    yolo_model_path = os.getenv("YOLO_MODEL_PATH") or "models/yolo11n.pt"

    return Settings(
        mongo_uri=mongo_uri,
        mongo_db_name=mongo_db_name,
        jwt_secret=jwt_secret,
        jwt_algorithm=jwt_algorithm,
        jwt_expiration_minutes=_parse_int("JWT_EXPIRATION_MINUTES", 480, 1, 43200),
        default_username=default_username,
        default_email=default_email,
        default_password=default_password,
        bcrypt_rounds=_parse_int("BCRYPT_ROUNDS", 12, 4, 31),
        smtp_host=smtp_host,
        smtp_port=_parse_int("SMTP_PORT", 587, 1, 65535),
        smtp_user=smtp_user,
        smtp_password=smtp_password,
        smtp_from=smtp_from,
        app_port=_parse_int("APP_PORT", 8000, 1, 65535),
        log_level=log_level,
        yolo_model_path=yolo_model_path,
        yolo_conf_threshold=_parse_float("YOLO_CONF_THRESHOLD", 0.35, 0.05, 0.99),
        yolo_imgsz_max=_parse_int("YOLO_IMGSZ_MAX", 640, 160, 1280),
        roi_padding_pct=_parse_float("ROI_PADDING_PCT", 0.15, 0.0, 0.50),
    )
