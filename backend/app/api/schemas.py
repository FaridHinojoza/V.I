"""Esquemas Pydantic v2 y validadores anti-inyección/XSS para el Sistema V.I."""

from __future__ import annotations

import re
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_USUARIO_RE = re.compile(r"^[A-Za-z0-9_.-]{2,50}$", re.ASCII)
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,54}\.[A-Za-z]{2,24}$",
    re.ASCII,
)
_CODIGO_RE = re.compile(r"^[0-9]{6}$", re.ASCII)

_NOSQL_JSON_RE = re.compile(r"\{\s*[\"']\$")
_NOSQL_OP_RE = re.compile(
    r"\$(?:ne|eq|gt|gte|lt|lte|in|nin|not|nor|or|and|where|regex|exists|"
    r"type|mod|all|size|elemMatch|expr|function|jsonSchema|accumulator|"
    r"text|search|comment|meta|slice|push|pull|set|unset|inc|rename|"
    r"lookup|match|group|project)\b",
    re.IGNORECASE,
)

_XSS_URI_RE = re.compile(r"(?:javascript|vbscript)\s*:", re.IGNORECASE)
_XSS_DATA_HTML_RE = re.compile(r"data\s*:\s*text/html", re.IGNORECASE)
_XSS_EVENT_HANDLER_RE = re.compile(r"\bon[a-z]{2,20}\s*=", re.IGNORECASE)

_SQLI_RE = re.compile(
    r"(?:"
    r"['\"]\s*(?:or|and)\s*['\"\d]"
    r"|['\"]\s*=\s*['\"]"
    r"|\b1\s*=\s*1\b"
    r"|['\"];?--"
    r"|;\s*--"
    r"|/\*|\*/"
    r"|;\s*(?:drop|select|insert|update|delete|shutdown)\b"
    r"|\b(?:union\s+(?:all\s+)?select|select\s+.+\s+from|insert\s+into|"
    r"update\s+.+\s+set|delete\s+from|drop\s+(?:table|database|schema)|"
    r"alter\s+table|exec(?:ute)?\s*\(|waitfor\s+delay|sleep\s*\()\b"
    r")",
    re.IGNORECASE,
)


def _assert_no_control_chars(value: str, field_name: str) -> None:
    if _CONTROL_CHAR_RE.search(value):
        raise ValueError(
            f"El campo '{field_name}' contiene caracteres de control no permitidos."
        )


def _assert_no_injection_or_xss(
    value: str,
    field_name: str,
    *,
    forbid_leading_dollar: bool = True,
) -> None:
    _assert_no_control_chars(value, field_name)

    if forbid_leading_dollar and value.lstrip().startswith("$"):
        raise ValueError(
            f"El campo '{field_name}' contiene un prefijo de operador no permitido."
        )
    if _NOSQL_JSON_RE.search(value) or _NOSQL_OP_RE.search(value):
        raise ValueError(
            f"El campo '{field_name}' contiene operadores no permitidos."
        )
    if (
        "<" in value
        or ">" in value
        or _XSS_URI_RE.search(value)
        or _XSS_DATA_HTML_RE.search(value)
        or _XSS_EVENT_HANDLER_RE.search(value)
    ):
        raise ValueError(
            f"El campo '{field_name}' contiene caracteres o patrones HTML/script no permitidos."
        )
    if _SQLI_RE.search(value):
        raise ValueError(
            f"El campo '{field_name}' contiene patrones de consulta no permitidos."
        )


def _validate_usuario_value(value: str) -> str:
    _assert_no_injection_or_xss(value, "usuario", forbid_leading_dollar=True)
    if value != value.strip():
        raise ValueError(
            "El campo 'usuario' no debe contener espacios al inicio o al final."
        )
    if not _USUARIO_RE.fullmatch(value):
        raise ValueError(
            "El campo 'usuario' debe tener entre 2 y 50 caracteres alfanuméricos válidos."
        )
    return value


def _validate_email_value(value: str) -> str:
    _assert_no_injection_or_xss(value, "correo", forbid_leading_dollar=True)
    if value != value.strip():
        raise ValueError(
            "El campo 'correo' no debe contener espacios al inicio o al final."
        )
    if len(value) < 5 or len(value) > 120 or ".." in value:
        raise ValueError("El campo 'correo' no tiene un formato válido.")
    if not _EMAIL_RE.fullmatch(value):
        raise ValueError("El campo 'correo' no tiene un formato válido.")
    local_part, domain_part = value.split("@", 1)
    if local_part.startswith(".") or local_part.endswith("."):
        raise ValueError("El campo 'correo' no tiene un formato válido.")
    for label in domain_part.split("."):
        if not label or label.startswith("-") or label.endswith("-"):
            raise ValueError("El campo 'correo' no tiene un formato válido.")
    return value


def _validate_password_value(
    value: str,
    field_name: str,
    *,
    min_chars: int,
    max_bytes: int = 72,
) -> str:
    _assert_no_injection_or_xss(value, field_name, forbid_leading_dollar=False)
    if value.strip() == "":
        raise ValueError(
            f"El campo '{field_name}' no puede estar vacío ni contener solo espacios."
        )
    if len(value) < min_chars:
        raise ValueError(
            f"El campo '{field_name}' debe tener al menos {min_chars} caracteres."
        )
    byte_len = len(value.encode("utf-8"))
    if byte_len > max_bytes:
        raise ValueError(
            f"El campo '{field_name}' no debe superar los {max_bytes} bytes UTF-8."
        )
    return value


class LoginRequest(BaseModel):
    """Esquema para POST /api/auth/login."""

    model_config = ConfigDict(extra="forbid")

    usuario: StrictStr
    clave: StrictStr

    @field_validator("usuario")
    @classmethod
    def validate_usuario(cls, value: str) -> str:
        return _validate_usuario_value(value)

    @field_validator("clave")
    @classmethod
    def validate_clave(cls, value: str) -> str:
        return _validate_password_value(value, "clave", min_chars=1, max_bytes=72)


class LogoutRequest(BaseModel):
    """Esquema para cuerpo de POST /api/auth/logout."""

    model_config = ConfigDict(extra="forbid")

    token: StrictStr

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str) -> str:
        _assert_no_injection_or_xss(value, "token", forbid_leading_dollar=True)
        if value != value.strip() or not value:
            raise ValueError("El campo 'token' es obligatorio y no debe tener espacios.")
        if len(value) > 2048:
            raise ValueError("El campo 'token' excede la longitud máxima permitida.")
        return value


class RecuperarSolicitarRequest(BaseModel):
    """Paso 1 para POST /api/auth/recuperar."""

    model_config = ConfigDict(extra="forbid")

    accion: Literal["solicitar_codigo"]
    correo: StrictStr

    @field_validator("correo")
    @classmethod
    def validate_correo(cls, value: str) -> str:
        return _validate_email_value(value)


class RecuperarActualizarRequest(BaseModel):
    """Paso 2 para POST /api/auth/recuperar."""

    model_config = ConfigDict(extra="forbid")

    accion: Literal["actualizar_clave"]
    correo: StrictStr
    codigo: StrictStr
    nueva_clave: StrictStr
    confirmar_clave: StrictStr

    @field_validator("correo")
    @classmethod
    def validate_correo(cls, value: str) -> str:
        return _validate_email_value(value)

    @field_validator("codigo")
    @classmethod
    def validate_codigo(cls, value: str) -> str:
        _assert_no_control_chars(value, "codigo")
        if not _CODIGO_RE.fullmatch(value):
            raise ValueError(
                "El campo 'codigo' debe contener exactamente 6 dígitos numéricos."
            )
        return value

    @field_validator("nueva_clave")
    @classmethod
    def validate_nueva_clave(cls, value: str) -> str:
        return _validate_password_value(
            value, "nueva_clave", min_chars=8, max_bytes=72
        )

    @field_validator("confirmar_clave")
    @classmethod
    def validate_confirmar_clave(cls, value: str) -> str:
        return _validate_password_value(
            value, "confirmar_clave", min_chars=8, max_bytes=72
        )


RecuperarRequest = Annotated[
    Union[RecuperarSolicitarRequest, RecuperarActualizarRequest],
    Field(discriminator="accion"),
]


class LoginResponse(BaseModel):
    token: str
    usuario: str
    mensaje: str


class LogoutResponse(BaseModel):
    mensaje: str


class VerificarResponse(BaseModel):
    valido: bool
    usuario: str


class RecuperarSolicitarResponse(BaseModel):
    mensaje: str
    correo: str


class RecuperarActualizarResponse(BaseModel):
    mensaje: str


class HealthResponse(BaseModel):
    status: str
