"""FastAPI application factory, lifespan seeding, security headers, and routes for Sistema V.I."""

from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes_auth import router as auth_router
from backend.app.api.routes_ws_monitoreo import router as monitoreo_router
from backend.app.api.schemas import HealthResponse
from backend.app.application.gestor_sesion import GestorSesionUnica
from backend.app.core.config import Settings, get_settings
from backend.app.infrastructure.repositorio_mongodb import RepositorioMongoDB

FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

_CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)


def _configure_logging(log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    root_logger = logging.getLogger()
    if not root_logger.handlers:
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        )
    else:
        root_logger.setLevel(level)


def _serve_html_page(filename: str) -> Response:
    target = FRONTEND_DIR / filename
    if target.is_file():
        return FileResponse(target, media_type="text/html; charset=utf-8")
    return JSONResponse(
        status_code=404,
        content={"detail": f"Vista '{filename}' aún no disponible."},
    )


def create_app(
    settings: Optional[Settings] = None,
    repositorio: Optional[RepositorioMongoDB] = None,
    gestor: Optional[GestorSesionUnica] = None,
) -> FastAPI:
    """Create and configure the Sistema V.I FastAPI application."""

    @asynccontextmanager
    async def lifespan(fastapi_app: FastAPI):
        active_settings = settings if settings is not None else get_settings()
        _configure_logging(active_settings.log_level)
        active_settings.validate_jwt_secret()

        owns_repo = repositorio is None
        if repositorio is None:
            active_repo = RepositorioMongoDB(
                uri_conexion=active_settings.mongo_uri,
                db_name=active_settings.mongo_db_name,
                default_username=active_settings.default_username,
                default_email=active_settings.default_email,
                default_password=active_settings.default_password,
                bcrypt_rounds=active_settings.bcrypt_rounds,
            )
            if not active_repo.esperar_conexion(max_retries=10, delay_seconds=1.0):
                active_repo.close()
                raise RuntimeError(
                    "No se pudo establecer conexión con MongoDB local."
                )
        else:
            active_repo = repositorio

        active_repo.inicializarCuentaUnica()
        active_gestor = (
            gestor
            if gestor is not None
            else GestorSesionUnica(
                repositorio=active_repo, settings=active_settings
            )
        )

        fastapi_app.state.settings = active_settings
        fastapi_app.state.repositorio = active_repo
        fastapi_app.state.gestor_sesion = active_gestor

        try:
            yield
        finally:
            if owns_repo:
                active_repo.close()

    fastapi_app = FastAPI(
        title="Sistema V.I — Control de Acceso y Monitoreo",
        version="1.0.0",
        lifespan=lifespan,
    )
    if settings is not None:
        fastapi_app.state.settings = settings
    if repositorio is not None:
        fastapi_app.state.repositorio = repositorio
    if gestor is not None:
        fastapi_app.state.gestor_sesion = gestor

    @fastapi_app.middleware("http")
    async def security_headers_middleware(request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = _CSP_POLICY
        response.headers["Permissions-Policy"] = (
            "camera=(self), microphone=(), geolocation=()"
        )
        if request.url.path.startswith("/api/auth"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @fastapi_app.exception_handler(RequestValidationError)
    async def sanitized_validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        sanitized_errors = [
            {
                "loc": list(err.get("loc", ())),
                "msg": str(err.get("msg", "Entrada inválida.")),
                "type": str(err.get("type", "value_error")),
            }
            for err in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": sanitized_errors})

    fastapi_app.include_router(auth_router)
    fastapi_app.include_router(monitoreo_router)

    @fastapi_app.get("/api/health", response_model=HealthResponse, tags=["Sistema"])
    def health_check() -> HealthResponse:
        return HealthResponse(status="ok")

    @fastapi_app.get("/", include_in_schema=False)
    def page_root() -> Response:
        return _serve_html_page("login.html")

    @fastapi_app.get("/login", include_in_schema=False)
    def page_login() -> Response:
        return _serve_html_page("login.html")

    @fastapi_app.get("/recuperar", include_in_schema=False)
    def page_recuperar() -> Response:
        return _serve_html_page("recuperar.html")

    @fastapi_app.get("/monitoreo", include_in_schema=False)
    def page_monitoreo() -> Response:
        return _serve_html_page("monitoreo.html")

    fastapi_app.mount(
        "/static",
        StaticFiles(directory=str(FRONTEND_DIR), check_dir=False),
        name="static",
    )

    return fastapi_app


app = create_app()
