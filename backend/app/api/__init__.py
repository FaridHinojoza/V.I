"""API routers and schemas for Sistema V.I."""

from backend.app.api.routes_auth import router as auth_router
from backend.app.api.routes_ws_monitoreo import router as monitoreo_router

__all__ = ["auth_router", "monitoreo_router"]
