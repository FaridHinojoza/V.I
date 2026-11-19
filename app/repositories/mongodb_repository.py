"""Local MongoDB persistence repository (RepositorioMongoDB) for Sistema V.I."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any, Optional

import bcrypt
from bson import ObjectId
from pymongo import DESCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.config import get_settings


class RepositorioMongoDB:
    """Encapsulates MongoDB collections and atomic US-01 persistence operations."""

    uriConexion: str
    dbName: str
    _client: Any
    _db: Database[dict[str, Any]]
    colUsuarios: Collection[dict[str, Any]]
    colAlertas: Collection[dict[str, Any]]
    colEvaluaciones: Collection[dict[str, Any]]

    def __init__(
        self,
        uri_conexion: Optional[str] = None,
        db_name: Optional[str] = None,
        default_username: Optional[str] = None,
        default_email: Optional[str] = None,
        default_password: Optional[str] = None,
        bcrypt_rounds: Optional[int] = None,
        server_selection_timeout_ms: int = 5000,
        connect_timeout_ms: int = 5000,
        socket_timeout_ms: int = 10000,
        client: Optional[Any] = None,
    ) -> None:
        settings = get_settings()

        self.uriConexion = (
            uri_conexion if uri_conexion is not None else settings.mongo_uri
        )
        self.dbName = db_name if db_name is not None else settings.mongo_db_name
        self._default_username = (
            default_username
            if default_username is not None
            else settings.default_username
        )
        self._default_email = (
            default_email if default_email is not None else settings.default_email
        )
        self._default_password = (
            default_password
            if default_password is not None
            else settings.default_password
        )
        self._bcrypt_rounds = (
            bcrypt_rounds if bcrypt_rounds is not None else settings.bcrypt_rounds
        )

        self._validar_str(self.uriConexion, "uri_conexion", prohibir_dolar=True)
        self._validar_str(self.dbName, "db_name", prohibir_dolar=True)
        self._validar_str(self._default_username, "default_username", prohibir_dolar=True)
        self._validar_str(self._default_email, "default_email", prohibir_dolar=True)
        self._validar_str(self._default_password, "default_password", prohibir_dolar=False)

        if not isinstance(self._bcrypt_rounds, int) or not (4 <= self._bcrypt_rounds <= 31):
            raise ValueError(
                f"bcrypt_rounds debe ser un entero entre 4 y 31, se recibió: {self._bcrypt_rounds!r}"
            )

        if client is None:
            self._client = MongoClient(
                self.uriConexion,
                serverSelectionTimeoutMS=server_selection_timeout_ms,
                connectTimeoutMS=connect_timeout_ms,
                socketTimeoutMS=socket_timeout_ms,
                tz_aware=True,
            )
        else:
            self._client = client

        self._db = self._client[self.dbName]
        self.colUsuarios = self._db["usuarios"]
        self.colAlertas = self._db["alertas"]
        self.colEvaluaciones = self._db["evaluaciones"]

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------
    def ping(self) -> bool:
        """Check whether the MongoDB server responds to ping."""
        try:
            res = self._client.admin.command("ping")
            return bool(res and res.get("ok") == 1)
        except PyMongoError:
            return False

    def esperar_conexion(
        self, max_retries: int = 5, delay_seconds: float = 1.0
    ) -> bool:
        """Retry ping until MongoDB responds or retries are exhausted."""
        if max_retries < 1:
            raise ValueError("max_retries debe ser al menos 1.")
        for attempt in range(max_retries):
            if self.ping():
                return True
            if attempt < max_retries - 1:
                time.sleep(delay_seconds)
        return False

    def close(self) -> None:
        """Close underlying MongoClient sockets if available."""
        if self._client is not None and hasattr(self._client, "close"):
            self._client.close()

    def __enter__(self) -> RepositorioMongoDB:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # NoSQLi / Input Validation Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _validar_str(
        valor: Any,
        campo: str,
        *,
        permitir_vacio: bool = False,
        prohibir_dolar: bool = True,
    ) -> str:
        if not isinstance(valor, str):
            raise ValueError(f"El campo '{campo}' debe ser una cadena escalar (str).")
        if "\x00" in valor:
            raise ValueError(f"El campo '{campo}' contiene bytes nulos inválidos.")
        if not permitir_vacio and valor == "":
            raise ValueError(f"El campo '{campo}' no puede estar vacío.")
        if prohibir_dolar and valor.startswith("$"):
            raise ValueError(
                f"El campo '{campo}' contiene un prefijo de operador no permitido ('$')."
            )
        return valor

    @classmethod
    def _validar_valor_documento(cls, valor: Any, ruta: str) -> Any:
        if isinstance(valor, str):
            if "\x00" in valor:
                raise ValueError(f"El valor en '{ruta}' contiene bytes nulos inválidos.")
            return valor
        if isinstance(valor, dict):
            return cls._validar_dict_seguro(valor, ruta)
        if isinstance(valor, list):
            return [
                cls._validar_valor_documento(item, f"{ruta}[{idx}]")
                for idx, item in enumerate(valor)
            ]
        return valor

    @classmethod
    def _validar_dict_seguro(cls, doc: Any, nombre: str) -> dict[str, Any]:
        if not isinstance(doc, dict):
            raise ValueError(f"'{nombre}' debe ser un diccionario.")
        sanitized: dict[str, Any] = {}
        for key, value in doc.items():
            if not isinstance(key, str) or key == "":
                raise ValueError(
                    f"Todas las claves en '{nombre}' deben ser cadenas no vacías."
                )
            if "\x00" in key:
                raise ValueError(
                    f"La clave '{key}' en '{nombre}' contiene bytes nulos inválidos."
                )
            if key.startswith("$"):
                raise ValueError(
                    f"La clave '{key}' en '{nombre}' comienza con '$' y no está permitida."
                )
            sanitized[key] = cls._validar_valor_documento(value, f"{nombre}.{key}")
        return sanitized

    # ------------------------------------------------------------------
    # US-01 Authentication & Seed Operations
    # ------------------------------------------------------------------
    def inicializarCuentaUnica(self) -> None:
        """Create unique indexes and idempotently seed the single operator account."""
        self.colUsuarios.create_index("usuario", unique=True, name="idx_usuario_unique")
        self.colUsuarios.create_index("correo", unique=True, name="idx_correo_unique")

        if self.colUsuarios.find_one({"usuario": self._default_username}) is not None:
            return

        password_bytes = self._default_password.encode("utf-8")
        if len(password_bytes) > 72:
            raise ValueError(
                "La contraseña inicial excede el límite de 72 bytes de Bcrypt."
            )

        password_hash = bcrypt.hashpw(
            password_bytes, bcrypt.gensalt(rounds=self._bcrypt_rounds)
        ).decode("utf-8")

        documento_semilla = {
            "usuario": self._default_username,
            "correo": self._default_email,
            "password_hash": password_hash,
            "token_sesion_unica": "",
            "codigo_recuperacion": "",
        }

        try:
            self.colUsuarios.insert_one(documento_semilla)
        except DuplicateKeyError:
            return

    def validarCredencialesUnicas(self, usuario: str) -> Optional[dict[str, Any]]:
        """Return the user document matching 'usuario', or None."""
        self._validar_str(usuario, "usuario", permitir_vacio=True, prohibir_dolar=True)
        if usuario == "":
            return None
        return self.colUsuarios.find_one({"usuario": usuario})

    def obtenerUsuarioPorCorreo(self, correo: str) -> Optional[dict[str, Any]]:
        """Return the user document matching 'correo', or None."""
        self._validar_str(correo, "correo", permitir_vacio=True, prohibir_dolar=True)
        if correo == "":
            return None
        return self.colUsuarios.find_one({"correo": correo})

    def actualizarTokenSesionUnica(self, usuario: str, token: str) -> bool:
        """Persist token_sesion_unica for the given user."""
        self._validar_str(usuario, "usuario", permitir_vacio=False, prohibir_dolar=True)
        self._validar_str(token, "token", permitir_vacio=True, prohibir_dolar=True)
        resultado = self.colUsuarios.update_one(
            {"usuario": usuario},
            {"$set": {"token_sesion_unica": token}},
        )
        return resultado.matched_count == 1

    def actualizarTokenSesionAtomico(
        self,
        usuario: str,
        expected_prev_token: Optional[str],
        new_token: str,
    ) -> bool:
        """Atomically update token_sesion_unica only if the stored token matches expected_prev_token."""
        self._validar_str(usuario, "usuario", permitir_vacio=False, prohibir_dolar=True)
        self._validar_str(new_token, "new_token", permitir_vacio=True, prohibir_dolar=True)

        if expected_prev_token is None or expected_prev_token == "":
            filtro: dict[str, Any] = {
                "usuario": usuario,
                "token_sesion_unica": {"$in": ["", None]},
            }
        else:
            self._validar_str(
                expected_prev_token,
                "expected_prev_token",
                permitir_vacio=False,
                prohibir_dolar=True,
            )
            filtro = {
                "usuario": usuario,
                "token_sesion_unica": expected_prev_token,
            }

        resultado = self.colUsuarios.update_one(
            filtro,
            {"$set": {"token_sesion_unica": new_token}},
        )
        return resultado.matched_count == 1

    def limpiarTokenSiCoincide(self, usuario: str, token: str) -> bool:
        """Atomically clear token_sesion_unica only when it matches the active token."""
        self._validar_str(usuario, "usuario", permitir_vacio=False, prohibir_dolar=True)
        self._validar_str(token, "token", permitir_vacio=True, prohibir_dolar=True)
        if token == "":
            return False

        resultado = self.colUsuarios.update_one(
            {"usuario": usuario, "token_sesion_unica": token},
            {"$set": {"token_sesion_unica": ""}},
        )
        return resultado.matched_count == 1

    def guardarCodigoRecuperacion(self, correo: str, codigo: str) -> bool:
        """Store the 6-digit recovery code on the user matching correo."""
        self._validar_str(correo, "correo", permitir_vacio=False, prohibir_dolar=True)
        self._validar_str(codigo, "codigo", permitir_vacio=False, prohibir_dolar=True)
        resultado = self.colUsuarios.update_one(
            {"correo": correo},
            {"$set": {"codigo_recuperacion": codigo}},
        )
        return resultado.matched_count == 1

    def actualizarPasswordHash(self, correo: str, nuevo_hash: str) -> bool:
        """Update password_hash and atomically clear recovery code and active session token."""
        self._validar_str(correo, "correo", permitir_vacio=False, prohibir_dolar=True)
        self._validar_str(
            nuevo_hash, "nuevo_hash", permitir_vacio=False, prohibir_dolar=False
        )
        resultado = self.colUsuarios.update_one(
            {"correo": correo},
            {
                "$set": {
                    "password_hash": nuevo_hash,
                    "codigo_recuperacion": "",
                    "token_sesion_unica": "",
                }
            },
        )
        return resultado.matched_count == 1

    # ------------------------------------------------------------------
    # Figura 4 UML Alert & Evaluation Operations
    # ------------------------------------------------------------------
    def guardarAlertaAutomatica(self, alerta: dict[str, Any]) -> ObjectId:
        """Insert a validated alert document into colAlertas."""
        doc = self._validar_dict_seguro(alerta, "alerta")
        doc.setdefault("fecha_evento", datetime.now(timezone.utc))
        return self.colAlertas.insert_one(doc).inserted_id

    def guardarEvaluacionAutomatica(self, evaluacion: dict[str, Any]) -> ObjectId:
        """Insert a validated evaluation document into colEvaluaciones."""
        doc = self._validar_dict_seguro(evaluacion, "evaluacion")
        doc.setdefault("fecha_evaluacion", datetime.now(timezone.utc))
        return self.colEvaluaciones.insert_one(doc).inserted_id

    def consultarAlertas(
        self,
        filtro_motivo: Optional[str] = None,
        *,
        filtroMotivo: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Query colAlertas sorted by fecha_evento descending, optionally filtered by motivo_alerta."""
        motivo = filtro_motivo if filtro_motivo is not None else filtroMotivo
        filtro: dict[str, Any] = {}
        if motivo is not None:
            self._validar_str(
                motivo, "filtro_motivo", permitir_vacio=True, prohibir_dolar=True
            )
            if motivo != "":
                filtro = {"motivo_alerta": motivo}
        return list(self.colAlertas.find(filtro).sort("fecha_evento", DESCENDING))
