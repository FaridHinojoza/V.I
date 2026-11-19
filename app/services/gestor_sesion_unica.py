"""Single-session authentication and two-step password recovery service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import logging
import re
import secrets
import smtplib
import threading
from typing import Any, Optional
import uuid

import bcrypt
import jwt

from app.config import Settings, get_settings
from app.repositories import RepositorioMongoDB

logger = logging.getLogger(__name__)

_ALLOWED_JWT_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_CODIGO_RE = re.compile(r"^[0-9]{6}$", re.ASCII)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_UNSET = object()

_DUMMY_HASH_LOCK = threading.Lock()
_DUMMY_HASHES_BY_ROUNDS: dict[int, bytes] = {}


class AuthError(Exception):
    """Base domain exception for authentication and recovery errors."""


class CredencialesInvalidasError(AuthError):
    """Raised when username/password verification fails."""


class SesionActivaError(CredencialesInvalidasError):
    """Raised when an active non-expired single session is already present."""


class TokenInvalidoError(AuthError):
    """Raised when a session JWT is missing, malformed, expired, or revoked."""


class CorreoNoRegistradoError(AuthError):
    """Raised when the requested recovery email is not registered."""


class CodigoRecuperacionInvalidoError(AuthError):
    """Raised when the recovery code is missing, malformed, or mismatched."""


class ContrasenasNoCoincidenError(AuthError):
    """Raised when nuevaClave and confirmarClave do not match."""


class ContrasenaInvalidaError(AuthError):
    """Raised when a new password violates length or character bounds."""


class EnvioCorreoError(AuthError):
    """Raised when configured SMTP delivery fails."""


def _get_dummy_bcrypt_hash(rounds: int) -> bytes:
    with _DUMMY_HASH_LOCK:
        cached = _DUMMY_HASHES_BY_ROUNDS.get(rounds)
        if cached is None:
            cached = bcrypt.hashpw(
                b"vi-constant-time-guard", bcrypt.gensalt(rounds=rounds)
            )
            _DUMMY_HASHES_BY_ROUNDS[rounds] = cached
        return cached


class GestorSesionUnica:
    """Manages non-recurrent single-session JWTs and 2-step password recovery."""

    sesionActivaToken: str
    rondasBcrypt: int

    def __init__(
        self,
        repositorio: Optional[RepositorioMongoDB] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        self._settings = settings if settings is not None else get_settings()
        self._settings.validate_jwt_secret()

        if self._settings.jwt_algorithm not in _ALLOWED_JWT_ALGORITHMS:
            raise ValueError(
                f"Algoritmo JWT no permitido: {self._settings.jwt_algorithm!r}"
            )

        self.rondasBcrypt = self._settings.bcrypt_rounds
        if not isinstance(self.rondasBcrypt, int) or not (4 <= self.rondasBcrypt <= 31):
            raise ValueError(
                f"rondasBcrypt debe estar entre 4 y 31, se recibió: {self.rondasBcrypt!r}"
            )

        self._repositorio = (
            repositorio if repositorio is not None else RepositorioMongoDB()
        )
        self.sesionActivaToken = ""

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------
    def _dummy_verify(self) -> None:
        dummy_hash = _get_dummy_bcrypt_hash(self.rondasBcrypt)
        bcrypt.checkpw(b"vi-dummy-password-probe", dummy_hash)

    def _verify_password(self, plain: Any, stored_hash: Any) -> bool:
        if not isinstance(plain, str) or not plain:
            self._dummy_verify()
            return False
        plain_bytes = plain.encode("utf-8")
        if len(plain_bytes) > 72:
            self._dummy_verify()
            return False
        if not isinstance(stored_hash, str) or not stored_hash:
            self._dummy_verify()
            return False
        try:
            return bcrypt.checkpw(plain_bytes, stored_hash.encode("utf-8"))
        except ValueError:
            return False

    def _decode_jwt(
        self, token: Any, *, verify_exp: bool = True
    ) -> Optional[dict[str, Any]]:
        if (
            not isinstance(token, str)
            or not token
            or "\x00" in token
            or token.startswith("$")
        ):
            return None
        try:
            payload = jwt.decode(
                token,
                self._settings.jwt_secret,
                algorithms=[self._settings.jwt_algorithm],
                options={"require": ["sub", "exp"], "verify_exp": verify_exp},
            )
        except (jwt.PyJWTError, ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        return payload

    def _lookup_user_by_email(self, correo: str) -> Optional[dict[str, Any]]:
        if not isinstance(correo, str) or "\x00" in correo:
            return None
        normalized = correo.strip()
        if not normalized or normalized.startswith("$"):
            return None
        user_doc = self._repositorio.obtenerUsuarioPorCorreo(normalized)
        if user_doc is None and normalized.lower() != normalized:
            user_doc = self._repositorio.obtenerUsuarioPorCorreo(normalized.lower())
        return user_doc

    # ------------------------------------------------------------------
    # US-01 Core Methods
    # ------------------------------------------------------------------
    def iniciarSesionUnica(self, usuario: str, clave: str) -> str:
        """Authenticate operator and acquire atomic single-session lock."""
        if (
            not isinstance(usuario, str)
            or not usuario
            or "\x00" in usuario
            or usuario.startswith("$")
            or not isinstance(clave, str)
            or not clave
            or "\x00" in clave
        ):
            self._dummy_verify()
            raise CredencialesInvalidasError(
                "Credenciales inválidas o sesión única ya activa."
            )

        user_doc = self._repositorio.validarCredencialesUnicas(usuario)
        if user_doc is None:
            self._dummy_verify()
            raise CredencialesInvalidasError(
                "Credenciales inválidas o sesión única ya activa."
            )

        if not self._verify_password(clave, user_doc.get("password_hash")):
            raise CredencialesInvalidasError(
                "Credenciales inválidas o sesión única ya activa."
            )

        prev_token = user_doc.get("token_sesion_unica")
        if prev_token is None or prev_token == "":
            expected_prev: Optional[str] = ""
        else:
            existing_payload = self._decode_jwt(prev_token, verify_exp=True)
            if (
                existing_payload is not None
                and existing_payload.get("sub") == usuario
            ):
                raise SesionActivaError(
                    "Credenciales inválidas o sesión única ya activa."
                )
            expected_prev = prev_token if isinstance(prev_token, str) else None

        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=self._settings.jwt_expiration_minutes)
        token_payload = {
            "sub": usuario,
            "iat": now,
            "exp": exp,
            "jti": uuid.uuid4().hex,
        }
        new_token = jwt.encode(
            token_payload,
            self._settings.jwt_secret,
            algorithm=self._settings.jwt_algorithm,
        )

        if (
            isinstance(expected_prev, str)
            and expected_prev != ""
            and (expected_prev.startswith("$") or "\x00" in expected_prev)
        ):
            # Defensive CAS fallback if DB stored an un-validatable corrupted string
            res = self._repositorio.colUsuarios.update_one(
                {"usuario": usuario, "token_sesion_unica": expected_prev},
                {"$set": {"token_sesion_unica": new_token}},
            )
            acquired = res.matched_count == 1
        else:
            acquired = self._repositorio.actualizarTokenSesionAtomico(
                usuario, expected_prev, new_token
            )

        if not acquired:
            raise SesionActivaError(
                "Credenciales inválidas o sesión única ya activa."
            )

        self.sesionActivaToken = new_token
        return new_token

    def verificarSesionUnicaActiva(self, token: str) -> Optional[str]:
        """Return username if JWT is valid, unexpired, and matches DB active token."""
        payload = self._decode_jwt(token, verify_exp=True)
        if payload is None:
            return None

        usuario = payload.get("sub")
        if (
            not isinstance(usuario, str)
            or not usuario
            or "\x00" in usuario
            or usuario.startswith("$")
        ):
            return None

        user_doc = self._repositorio.validarCredencialesUnicas(usuario)
        if user_doc is None:
            return None

        stored_token = user_doc.get("token_sesion_unica")
        if not isinstance(stored_token, str) or not stored_token:
            return None

        if not secrets.compare_digest(stored_token, token):
            return None

        return usuario

    def cerrarSesionUnica(self, token: str) -> bool:
        """Clear token_sesion_unica in MongoDB only if token matches active JWT."""
        payload = self._decode_jwt(token, verify_exp=True)
        if payload is None:
            return False

        usuario = payload.get("sub")
        if (
            not isinstance(usuario, str)
            or not usuario
            or "\x00" in usuario
            or usuario.startswith("$")
        ):
            return False

        cleared = self._repositorio.limpiarTokenSiCoincide(usuario, token)
        if cleared and self.sesionActivaToken == token:
            self.sesionActivaToken = ""
        return cleared

    def enviarCodigoRecuperacion(self, correo: str) -> str:
        """Generate and persist a 6-digit CSPRNG code and deliver via SMTP or log."""
        user_doc = self._lookup_user_by_email(correo)
        if user_doc is None:
            raise CorreoNoRegistradoError(
                "El correo electrónico no se encuentra registrado."
            )

        correo_db = user_doc["correo"]
        codigo = f"{secrets.randbelow(1_000_000):06d}"

        if not self._repositorio.guardarCodigoRecuperacion(correo_db, codigo):
            raise CorreoNoRegistradoError(
                "El correo electrónico no se encuentra registrado."
            )

        smtp_host = self._settings.smtp_host.strip()
        smtp_user = self._settings.smtp_user.strip()

        if smtp_host and smtp_user:
            msg = EmailMessage()
            msg["Subject"] = "Sistema V.I — Código de recuperación de contraseña"
            msg["From"] = self._settings.smtp_from
            msg["To"] = correo_db
            msg.set_content(
                "Estimado operador,\n\n"
                f"Su código de recuperación de 6 dígitos para el Sistema V.I es: {codigo}\n\n"
                "Si no solicitó este cambio, ignore este mensaje.\n"
            )
            try:
                if self._settings.smtp_port == 465:
                    with smtplib.SMTP_SSL(
                        smtp_host, self._settings.smtp_port, timeout=10
                    ) as smtp:
                        smtp.login(smtp_user, self._settings.smtp_password)
                        smtp.send_message(msg)
                else:
                    with smtplib.SMTP(
                        smtp_host, self._settings.smtp_port, timeout=10
                    ) as smtp:
                        smtp.ehlo()
                        smtp.starttls()
                        smtp.ehlo()
                        smtp.login(smtp_user, self._settings.smtp_password)
                        smtp.send_message(msg)
            except (OSError, smtplib.SMTPException) as exc:
                logger.error(
                    "SMTP_ERROR correo=%s host=%s error=%s",
                    correo_db,
                    smtp_host,
                    type(exc).__name__,
                )
                raise EnvioCorreoError(
                    "No se pudo enviar el código de recuperación por correo electrónico."
                ) from exc

            logger.info("RECOVERY_EMAIL_SENT correo=%s", correo_db)
        else:
            logger.info("RECOVERY_CODE correo=%s codigo=%s", correo_db, codigo)
            print(f"RECOVERY_CODE correo={correo_db} codigo={codigo}", flush=True)

        return codigo

    def actualizarContrasena(
        self,
        correo: str,
        codigo: str,
        nuevaClave: str,
        confirmarClave: Any = _UNSET,
    ) -> bool:
        """Verify recovery code, hash new password (Bcrypt 12 rounds), and clear session."""
        if not isinstance(codigo, str) or not _CODIGO_RE.fullmatch(codigo):
            raise CodigoRecuperacionInvalidoError(
                "Código de recuperación inválido o expirado."
            )

        if (
            not isinstance(nuevaClave, str)
            or nuevaClave.strip() == ""
            or _CONTROL_CHAR_RE.search(nuevaClave)
        ):
            raise ContrasenaInvalidaError(
                "La nueva contraseña debe tener entre 8 y 72 bytes UTF-8 válidos."
            )

        nueva_bytes = nuevaClave.encode("utf-8")
        if len(nueva_bytes) < 8 or len(nueva_bytes) > 72:
            raise ContrasenaInvalidaError(
                "La nueva contraseña debe tener entre 8 y 72 bytes UTF-8 válidos."
            )

        if confirmarClave is not _UNSET:
            if not isinstance(confirmarClave, str) or not secrets.compare_digest(
                nuevaClave, confirmarClave
            ):
                raise ContrasenasNoCoincidenError("Las contraseñas no coinciden.")

        user_doc = self._lookup_user_by_email(correo)
        if user_doc is None:
            raise CorreoNoRegistradoError(
                "El correo electrónico no se encuentra registrado."
            )

        stored_code = user_doc.get("codigo_recuperacion", "")
        if not isinstance(stored_code, str) or not stored_code:
            raise CodigoRecuperacionInvalidoError(
                "Código de recuperación inválido o expirado."
            )

        if not secrets.compare_digest(stored_code, codigo):
            raise CodigoRecuperacionInvalidoError(
                "Código de recuperación inválido o expirado."
            )

        nuevo_hash = bcrypt.hashpw(
            nueva_bytes, bcrypt.gensalt(rounds=self.rondasBcrypt)
        ).decode("utf-8")

        if not self._repositorio.actualizarPasswordHash(
            user_doc["correo"], nuevo_hash
        ):
            raise CorreoNoRegistradoError(
                "El correo electrónico no se encuentra registrado."
            )

        self.sesionActivaToken = ""
        return True
