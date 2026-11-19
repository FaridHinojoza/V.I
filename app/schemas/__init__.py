"""Pydantic v2 request and response schemas for Sistema V.I authentication."""

from app.schemas.auth_schemas import (
    HealthResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    RecuperarActualizarRequest,
    RecuperarActualizarResponse,
    RecuperarRequest,
    RecuperarSolicitarRequest,
    RecuperarSolicitarResponse,
    VerificarResponse,
)

__all__ = [
    "HealthResponse",
    "LoginRequest",
    "LoginResponse",
    "LogoutRequest",
    "LogoutResponse",
    "RecuperarActualizarRequest",
    "RecuperarActualizarResponse",
    "RecuperarRequest",
    "RecuperarSolicitarRequest",
    "RecuperarSolicitarResponse",
    "VerificarResponse",
]
