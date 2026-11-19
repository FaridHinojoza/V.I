"""REST authentication endpoints for US-01 (/api/auth/*)."""

from __future__ import annotations

import json
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import ValidationError
from pymongo.errors import PyMongoError

from app.config import get_settings
from app.repositories import RepositorioMongoDB
from app.schemas.auth_schemas import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    LogoutResponse,
    RecuperarActualizarResponse,
    RecuperarRequest,
    RecuperarSolicitarRequest,
    RecuperarSolicitarResponse,
    VerificarResponse,
)
from app.services import (
    CodigoRecuperacionInvalidoError,
    ContrasenaInvalidaError,
    ContrasenasNoCoincidenError,
    CorreoNoRegistradoError,
    CredencialesInvalidasError,
    EnvioCorreoError,
    GestorSesionUnica,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Autenticación"])


def get_gestor_sesion(request: Request) -> GestorSesionUnica:
    """Resolve GestorSesionUnica from app.state with lazy fallback for non-lifespan tests."""
    gestor = getattr(request.app.state, "gestor_sesion", None)
    if gestor is not None:
        return gestor

    repo = getattr(request.app.state, "repositorio", None)
    if repo is None:
        repo = RepositorioMongoDB()
        request.app.state.repositorio = repo

    settings = getattr(request.app.state, "settings", None)
    if settings is None:
        settings = get_settings()
        request.app.state.settings = settings

    gestor = GestorSesionUnica(repositorio=repo, settings=settings)
    request.app.state.gestor_sesion = gestor
    return gestor


def _extract_bearer_token(authorization: Optional[str]) -> str:
    if not authorization or not isinstance(authorization, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1].strip()
    if (
        not token
        or token.startswith("$")
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in token)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


def _sanitize_validation_errors(exc: ValidationError) -> list[dict[str, object]]:
    return [
        {
            "loc": list(err.get("loc", ())),
            "msg": str(err.get("msg", "Entrada inválida.")),
            "type": str(err.get("type", "value_error")),
        }
        for err in exc.errors()
    ]


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    gestor: GestorSesionUnica = Depends(get_gestor_sesion),
) -> LoginResponse:
    """Authenticate single operator account and return unique session JWT."""
    try:
        token = gestor.iniciarSesionUnica(payload.usuario, payload.clave)
    except CredencialesInvalidasError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas o sesión única ya activa.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except PyMongoError as exc:
        logger.error("MongoDB error during /api/auth/login: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de base de datos temporalmente no disponible.",
        ) from exc

    return LoginResponse(
        token=token,
        usuario=payload.usuario,
        mensaje="Inicio de sesión exitoso.",
    )


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    gestor: GestorSesionUnica = Depends(get_gestor_sesion),
) -> LogoutResponse:
    """Release single-session lock via Bearer header or JSON/text-plain sendBeacon body."""
    header_token: Optional[str] = None
    if authorization is not None:
        header_token = _extract_bearer_token(authorization)

    raw_body = await request.body()
    body_token: Optional[str] = None
    if raw_body and raw_body.strip():
        try:
            decoded = raw_body.decode("utf-8")
            parsed = json.loads(decoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HTTPException(
                status_code=422,
                detail=[
                    {
                        "loc": ["body"],
                        "msg": "El cuerpo de la solicitud debe ser JSON válido.",
                        "type": "json_invalid",
                    }
                ],
            ) from exc

        if not isinstance(parsed, dict):
            raise HTTPException(
                status_code=422,
                detail=[
                    {
                        "loc": ["body"],
                        "msg": "El cuerpo debe ser un objeto JSON.",
                        "type": "dict_type",
                    }
                ],
            )

        try:
            validated_body = LogoutRequest.model_validate(parsed)
        except ValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail=_sanitize_validation_errors(exc),
            ) from exc

        body_token = validated_body.token

    if header_token is not None and body_token is not None:
        if not secrets.compare_digest(header_token, body_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sesión inválida, expirada o cerrada.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = header_token
    elif header_token is not None:
        token = header_token
    elif body_token is not None:
        token = body_token
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        cerrada = gestor.cerrarSesionUnica(token)
    except PyMongoError as exc:
        logger.error("MongoDB error during /api/auth/logout: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de base de datos temporalmente no disponible.",
        ) from exc

    if not cerrada:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return LogoutResponse(mensaje="Sesión cerrada correctamente.")


@router.get("/verificar", response_model=VerificarResponse)
@router.get("/verify", response_model=VerificarResponse)
def verificar_sesion(
    authorization: Optional[str] = Header(default=None),
    gestor: GestorSesionUnica = Depends(get_gestor_sesion),
) -> VerificarResponse:
    """Validate Bearer JWT signature, expiration, and active DB match."""
    token = _extract_bearer_token(authorization)
    try:
        usuario = gestor.verificarSesionUnicaActiva(token)
    except PyMongoError as exc:
        logger.error("MongoDB error during /api/auth/verificar: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de base de datos temporalmente no disponible.",
        ) from exc

    if not isinstance(usuario, str) or not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida, expirada o cerrada.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return VerificarResponse(valido=True, usuario=usuario)


@router.post(
    "/recuperar",
    response_model=RecuperarSolicitarResponse | RecuperarActualizarResponse,
)
def recuperar_contrasena(
    payload: RecuperarRequest,
    gestor: GestorSesionUnica = Depends(get_gestor_sesion),
) -> RecuperarSolicitarResponse | RecuperarActualizarResponse:
    """Two-step password recovery: solicitar_codigo and actualizar_clave."""
    try:
        if isinstance(payload, RecuperarSolicitarRequest):
            gestor.enviarCodigoRecuperacion(payload.correo)
            return RecuperarSolicitarResponse(
                mensaje="Código enviado al correo registrado.",
                correo=payload.correo,
            )

        gestor.actualizarContrasena(
            payload.correo,
            payload.codigo,
            payload.nueva_clave,
            payload.confirmar_clave,
        )
        return RecuperarActualizarResponse(
            mensaje="Contraseña actualizada correctamente."
        )
    except CorreoNoRegistradoError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="El correo electrónico no se encuentra registrado.",
        ) from exc
    except CodigoRecuperacionInvalidoError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Código de recuperación inválido o expirado.",
        ) from exc
    except ContrasenasNoCoincidenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Las contraseñas no coinciden.",
        ) from exc
    except ContrasenaInvalidaError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La nueva contraseña no cumple los requisitos de seguridad.",
        ) from exc
    except EnvioCorreoError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo enviar el código de recuperación por correo electrónico.",
        ) from exc
    except PyMongoError as exc:
        logger.error("MongoDB error during /api/auth/recuperar: %s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Servicio de base de datos temporalmente no disponible.",
        ) from exc
