"""FastAPI routers for Sistema V.I."""

from app.routers.auth_router import get_gestor_sesion, router

__all__ = ["get_gestor_sesion", "router"]
