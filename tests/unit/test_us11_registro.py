"""Unit, security, multi-user isolation, and UI route tests for US-11 (RF-17 / CP-09)."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional

import bcrypt
from bson import ObjectId
from fastapi.testclient import TestClient
import pytest
from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError

from backend.app.application.gestor_sesion import (
    ContrasenaInvalidaError,
    ContrasenasNoCoincidenError,
    GestorSesionUnica,
    UsuarioOCorreoDuplicadoError,
)
from backend.app.core.config import Settings
from backend.app.infrastructure.repositorio_mongodb import RepositorioMongoDB
from backend.app.main import create_app

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"


class _FakeInsertResult:
    def __init__(self, inserted_id: ObjectId) -> None:
        self.inserted_id = inserted_id


class _FakeUpdateResult:
    def __init__(self, matched_count: int) -> None:
        self.matched_count = matched_count


class _FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self._docs = docs

    def sort(self, key: str, direction: int) -> _FakeCursor:
        self._docs.sort(key=lambda d: d.get(key), reverse=(direction == DESCENDING))
        return self

    def __iter__(self):
        return iter(self._docs)


class _FakeCollection:
    def __init__(self, unique_fields: tuple[str, ...] = ()) -> None:
        self._docs: list[dict[str, Any]] = []
        self._unique_fields = set(unique_fields)

    def create_index(self, field: str, unique: bool = False, name: str = "") -> str:
        if unique:
            self._unique_fields.add(field)
        return name or f"idx_{field}"

    @staticmethod
    def _matches(doc: dict[str, Any], filtro: dict[str, Any]) -> bool:
        for k, v in filtro.items():
            if k == "$or":
                if not any(_FakeCollection._matches(doc, sub) for sub in v):
                    return False
            elif isinstance(v, dict) and "$in" in v:
                if doc.get(k) not in v["$in"]:
                    return False
            elif doc.get(k) != v:
                return False
        return True

    def find_one(
        self, filtro: dict[str, Any], projection: Optional[dict[str, int]] = None
    ) -> Optional[dict[str, Any]]:
        for d in self._docs:
            if self._matches(d, filtro):
                return deepcopy(d)
        return None

    def find(self, filtro: dict[str, Any]) -> _FakeCursor:
        return _FakeCursor([deepcopy(d) for d in self._docs if self._matches(d, filtro)])

    def insert_one(self, doc: dict[str, Any]) -> _FakeInsertResult:
        for uf in self._unique_fields:
            if uf in doc and any(existing.get(uf) == doc[uf] for existing in self._docs):
                raise DuplicateKeyError(f"Duplicate key on {uf}")
        stored = deepcopy(doc)
        stored.setdefault("_id", ObjectId())
        self._docs.append(stored)
        return _FakeInsertResult(stored["_id"])

    def update_one(self, filtro: dict[str, Any], update: dict[str, Any]) -> _FakeUpdateResult:
        for d in self._docs:
            if self._matches(d, filtro):
                for k, v in update.get("$set", {}).items():
                    d[k] = v
                return _FakeUpdateResult(1)
        return _FakeUpdateResult(0)


class _FakeMongoClient:
    def __init__(self) -> None:
        self._cols = {
            "usuarios": _FakeCollection(("usuario", "correo")),
            "alertas": _FakeCollection(),
            "evaluaciones": _FakeCollection(),
        }

    def __getitem__(self, name: str) -> dict[str, _FakeCollection]:
        return self._cols


def _make_settings() -> Settings:
    return Settings(
        mongo_uri="mongodb://localhost:27017",
        mongo_db_name="vi_test",
        jwt_secret=_TEST_JWT_SECRET,
        jwt_algorithm="HS256",
        jwt_expiration_minutes=60,
        default_username="admin_seed",
        default_email="seed@espe.edu.ec",
        default_password="SeedPassword123!",
        bcrypt_rounds=4,
        smtp_host="",
        smtp_port=587,
        smtp_user="",
        smtp_password="",
        smtp_from="no-reply@vi.local",
        app_port=8000,
        log_level="INFO",
    )


def _make_client() -> tuple[TestClient, RepositorioMongoDB, GestorSesionUnica]:
    settings = _make_settings()
    repo = RepositorioMongoDB(
        uri_conexion=settings.mongo_uri,
        db_name=settings.mongo_db_name,
        default_username=settings.default_username,
        default_email=settings.default_email,
        default_password=settings.default_password,
        bcrypt_rounds=settings.bcrypt_rounds,
        client=_FakeMongoClient(),
    )
    repo.inicializarCuentaUnica()
    gestor = GestorSesionUnica(repositorio=repo, settings=settings)
    app = create_app(settings=settings, repositorio=repo, gestor=gestor)
    return TestClient(app), repo, gestor


def test_registro_directo_exitoso_y_login() -> None:
    """CP-09: Registro directo crea usuario con Bcrypt, sin roles, y permite login."""
    client, repo, _ = _make_client()
    res = client.post(
        "/api/auth/registro",
        json={
            "usuario": "operador_nuevo",
            "correo": "Operador@espe.edu.ec",
            "clave": "ClaveSegura123",
            "confirmar_clave": "ClaveSegura123",
        },
    )
    assert res.status_code == 201
    assert res.json()["usuario"] == "operador_nuevo"

    doc = repo.validarCredencialesUnicas("operador_nuevo")
    assert doc is not None
    assert doc["correo"] == "operador@espe.edu.ec"
    assert doc["token_sesion_unica"] == ""
    assert "rol" not in doc
    assert bcrypt.checkpw(b"ClaveSegura123", doc["password_hash"].encode("utf-8"))

    login_res = client.post(
        "/api/auth/login",
        json={"usuario": "operador_nuevo", "clave": "ClaveSegura123"},
    )
    assert login_res.status_code == 200
    assert isinstance(login_res.json()["token"], str)


def test_registro_rechaza_contrasenas_distintas_y_duplicados() -> None:
    """CP-09: Rechaza claves distintas (400) y usuario o correo duplicado (409)."""
    client, _, _ = _make_client()

    mismatch = client.post(
        "/api/auth/registro",
        json={
            "usuario": "operador_a",
            "correo": "a@espe.edu.ec",
            "clave": "ClaveSegura123",
            "confirmar_clave": "OtraClave123",
        },
    )
    assert mismatch.status_code == 400

    ok = client.post(
        "/api/auth/registro",
        json={
            "usuario": "operador_a",
            "correo": "a@espe.edu.ec",
            "clave": "ClaveSegura123",
            "confirmar_clave": "ClaveSegura123",
        },
    )
    assert ok.status_code == 201

    dup_user = client.post(
        "/api/auth/registro",
        json={
            "usuario": "operador_a",
            "correo": "otro@espe.edu.ec",
            "clave": "ClaveSegura123",
            "confirmar_clave": "ClaveSegura123",
        },
    )
    assert dup_user.status_code == 409

    dup_email = client.post(
        "/api/auth/registro",
        json={
            "usuario": "operador_b",
            "correo": "A@espe.edu.ec",
            "clave": "ClaveSegura123",
            "confirmar_clave": "ClaveSegura123",
        },
    )
    assert dup_email.status_code == 409


def test_registro_rechaza_inyecciones_y_valida_dominio() -> None:
    """Bloquea cargas NoSQLi/XSS/control en /api/auth/registro y valida dominio."""
    client, _, gestor = _make_client()

    for bad_payload in [
        {"usuario": "$ne", "correo": "x@espe.edu.ec", "clave": "ClaveSegura123", "confirmar_clave": "ClaveSegura123"},
        {"usuario": "user<script>", "correo": "x@espe.edu.ec", "clave": "ClaveSegura123", "confirmar_clave": "ClaveSegura123"},
        {"usuario": "user_ok", "correo": "x@espe.edu.ec", "clave": "corta", "confirmar_clave": "corta"},
    ]:
        res = client.post("/api/auth/registro", json=bad_payload)
        assert res.status_code == 422

    with pytest.raises(ContrasenaInvalidaError):
        gestor.registrarUsuario("u1", "u1@espe.edu.ec", "123", "123")
    with pytest.raises(ContrasenasNoCoincidenError):
        gestor.registrarUsuario("u1", "u1@espe.edu.ec", "ClaveSegura123", "Distinta123")
    gestor.registrarUsuario("u1", "u1@espe.edu.ec", "ClaveSegura123", "ClaveSegura123")
    with pytest.raises(UsuarioOCorreoDuplicadoError):
        gestor.registrarUsuario("u1", "u2@espe.edu.ec", "ClaveSegura123", "ClaveSegura123")


def test_multiusuario_sesion_unica_por_usuario_y_datos_aislados() -> None:
    """RNF-03: Usuarios distintos operan independientes; misma cuenta bloquea doble sesión."""
    client, repo, _ = _make_client()
    for user, mail in [("op1", "op1@espe.edu.ec"), ("op2", "op2@espe.edu.ec")]:
        assert client.post(
            "/api/auth/registro",
            json={"usuario": user, "correo": mail, "clave": "ClaveSegura123", "confirmar_clave": "ClaveSegura123"},
        ).status_code == 201

    r1 = client.post("/api/auth/login", json={"usuario": "op1", "clave": "ClaveSegura123"})
    r2 = client.post("/api/auth/login", json={"usuario": "op2", "clave": "ClaveSegura123"})
    assert r1.status_code == 200 and r2.status_code == 200
    assert client.post("/api/auth/login", json={"usuario": "op1", "clave": "ClaveSegura123"}).status_code == 401

    uid1 = repo.validarCredencialesUnicas("op1")["_id"]
    uid2 = repo.validarCredencialesUnicas("op2")["_id"]
    repo.guardarAlertaAutomatica({"track_id": 1, "motivo_alerta": "tiempo", "tiempo_estancia_seg": 12.0, "captura_jpg": "x"}, usuario_id=uid1)
    repo.guardarAlertaAutomatica({"track_id": 2, "motivo_alerta": "trayectoria", "tiempo_estancia_seg": 8.0, "captura_jpg": "y"}, usuario_id=uid2)
    repo.guardarEvaluacionAutomatica({"nombre_video": "v1.mp4"}, usuario_id=uid1)

    assert len(repo.consultarAlertas(usuario_id=uid1)) == 1
    assert repo.consultarAlertas(usuario_id=uid1)[0]["track_id"] == 1
    assert len(repo.consultarEvaluaciones(usuario_id=uid1)) == 1
    assert len(repo.consultarEvaluaciones(usuario_id=uid2)) == 0


def test_vistas_login_y_registro_y_headers() -> None:
    """Verifica enlace Registrarse en /login, vista /registro y headers Cache-Control."""
    client, _, _ = _make_client()
    login_html = client.get("/login")
    reg_html = client.get("/registro")
    assert login_html.status_code == 200
    assert 'href="/registro"' in login_html.text
    assert "Registrarse" in login_html.text

    assert reg_html.status_code == 200
    assert "Registro de usuario" in reg_html.text
    assert "/static/js/registro.js" in reg_html.text

    api_res = client.post(
        "/api/auth/registro",
        json={"usuario": "u_hdr", "correo": "uh@espe.edu.ec", "clave": "ClaveSegura123", "confirmar_clave": "ClaveSegura123"},
    )
    assert api_res.headers.get("Cache-Control") == "no-store"
