"""Service layer exports for Sistema V.I."""

from app.services.gestor_sesion_unica import (
    AuthError,
    CodigoRecuperacionInvalidoError,
    ContrasenaInvalidaError,
    ContrasenasNoCoincidenError,
    CorreoNoRegistradoError,
    CredencialesInvalidasError,
    EnvioCorreoError,
    GestorSesionUnica,
    SesionActivaError,
    TokenInvalidoError,
)

__all__ = [
    "AuthError",
    "CodigoRecuperacionInvalidoError",
    "ContrasenaInvalidaError",
    "ContrasenasNoCoincidenError",
    "CorreoNoRegistradoError",
    "CredencialesInvalidasError",
    "EnvioCorreoError",
    "GestorSesionUnica",
    "SesionActivaError",
    "TokenInvalidoError",
]
