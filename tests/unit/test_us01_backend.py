"""Unit, security, concurrency, and live-container tests for Milestone M2 (US-01 Backend)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import logging
import os
import re
import smtplib
import threading
from typing import Any, Optional
import uuid

import bcrypt
from bson import ObjectId
from fastapi.testclient import TestClient
import jwt
import pytest
from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError, PyMongoError

from app.config import Settings
from app.main import create_app
from app.repositories import RepositorioMongoDB
from app.routers.auth_router import get_gestor_sesion
from app.services import (
    ContrasenasNoCoincidenError,
    GestorSesionUnica,
    SesionActivaError,
)

_TEST_JWT_SECRET = "9f4b2c8e1a7d6f035b9e2c4a8d1f7036e5b9c2a4d8f1036e9b2c5a8d1f407362"
_EXPECTED_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'"
)


# ---------------------------------------------------------------------------
# Self-contained thread-safe in-memory PyMongo fake for M2 unit tests
# ---------------------------------------------------------------------------
class _FakeUpdateResult:
    def __init__(self, matched_count: int, modified_count: int) -> None:
        self.matched_count = matched_count
        self.modified_count = modified_count


class _FakeInsertResult:
    def __init__(self, inserted_id: ObjectId) -> None:
        self.inserted_id = inserted_id


class _FakeCursor:
    def __init__(self, docs: list[dict[str, Any]]) -> None:
        self._docs = docs

    def sort(self, key: str, direction: int) -> _FakeCursor:
        reverse = direction == DESCENDING
        self._docs.sort(key=lambda d: d.get(key), reverse=reverse)
        return self

    def __iter__(self):
        return iter(self._docs)


class _FakeCollection:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._docs: list[dict[str, Any]] = []
        self._indexes: dict[str, dict[str, Any]] = {
            "_id_": {"key": [("_id", 1)], "unique": True}
        }

    @staticmethod
    def _matches(doc: dict[str, Any], filtro: dict[str, Any]) -> bool:
        for field, expected in filtro.items():
            actual = doc.get(field, None)
            if isinstance(expected, dict) and "$in" in expected:
                if actual not in expected["$in"]:
                    return False
            elif actual != expected:
                return False
        return True

    def create_index(
        self, field: str, unique: bool = False, name: Optional[str] = None
    ) -> str:
        idx_name = name or f"{field}_1"
        with self._lock:
            self._indexes[idx_name] = {"key": [(field, 1)], "unique": unique}
        return idx_name

    def find_one(self, filtro: dict[str, Any]) -> Optional[dict[str, Any]]:
        with self._lock:
            for doc in self._docs:
                if self._matches(doc, filtro):
                    return deepcopy(doc)
        return None

    def find(self, filtro: Optional[dict[str, Any]] = None) -> _FakeCursor:
        query = filtro or {}
        with self._lock:
            matched = [deepcopy(d) for d in self._docs if self._matches(d, query)]
        return _FakeCursor(matched)

    def insert_one(self, doc: dict[str, Any]) -> _FakeInsertResult:
        with self._lock:
            new_doc = deepcopy(doc)
            if "_id" not in new_doc:
                new_doc["_id"] = ObjectId()
            for idx_meta in self._indexes.values():
                if not idx_meta.get("unique"):
                    continue
                field = idx_meta["key"][0][0]
                if field in new_doc:
                    for existing in self._docs:
                        if existing.get(field) == new_doc[field]:
                            raise DuplicateKeyError(
                                f"E11000 duplicate key error on {field}"
                            )
            self._docs.append(new_doc)
            return _FakeInsertResult(new_doc["_id"])

    def update_one(
        self, filtro: dict[str, Any], update: dict[str, Any]
    ) -> _FakeUpdateResult:
        with self._lock:
            for doc in self._docs:
                if self._matches(doc, filtro):
                    set_fields = update.get("$set", {})
                    modified = 0
                    for k, v in set_fields.items():
                        if doc.get(k) != v:
                            modified = 1
                        doc[k] = deepcopy(v)
                    return _FakeUpdateResult(matched_count=1, modified_count=modified)
            return _FakeUpdateResult(matched_count=0, modified_count=0)


class _FakeDatabase:
    def __init__(self) -> None:
        self._collections: dict[str, _FakeCollection] = {}

    def __getitem__(self, name: str) -> _FakeCollection:
        if name not in self._collections:
            self._collections[name] = _FakeCollection()
        return self._collections[name]


class _FakeAdmin:
    def __init__(self, ping_ok: bool = True) -> None:
        self._ping_ok = ping_ok

    def command(self, cmd: str) -> dict[str, Any]:
        if cmd == "ping" and self._ping_ok:
            return {"ok": 1}
        return {"ok": 0}


class _FakeMongoClient:
    def __init__(self, ping_ok: bool = True) -> None:
        self.admin = _FakeAdmin(ping_ok=ping_ok)
        self._dbs: dict[str, _FakeDatabase] = {}
        self.closed = False

    def __getitem__(self, name: str) -> _FakeDatabase:
        if name not in self._dbs:
            self._dbs[name] = _FakeDatabase()
        return self._dbs[name]

    def close(self) -> None:
        self.closed = True


def _make_settings(**overrides: Any) -> Settings:
    data: dict[str, Any] = {
        "mongo_uri": "mongodb://mongodb:27017",
        "mongo_db_name": "vi_unit_db",
        "jwt_secret": _TEST_JWT_SECRET,
        "jwt_algorithm": "HS256",
        "jwt_expiration_minutes": 480,
        "default_username": "vi",
        "default_email": "dsceli@espe.edu.ec",
        "default_password": "OperadorVI2026*",
        "bcrypt_rounds": 12,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_user": "",
        "smtp_password": "",
        "smtp_from": "no-reply@espe.edu.ec",
        "app_port": 8000,
        "log_level": "INFO",
    }
    data.update(overrides)
    return Settings(**data)


def _make_fake_env(**setting_overrides: Any):
    settings = _make_settings(**setting_overrides)
    fake_client = _FakeMongoClient()
    repo = RepositorioMongoDB(
        uri_conexion=settings.mongo_uri,
        db_name=settings.mongo_db_name,
        default_username=settings.default_username,
        default_email=settings.default_email,
        default_password=settings.default_password,
        bcrypt_rounds=settings.bcrypt_rounds,
        client=fake_client,
    )
    gestor = GestorSesionUnica(repositorio=repo, settings=settings)
    fastapi_app = create_app(settings=settings, repositorio=repo, gestor=gestor)
    return fastapi_app, repo, gestor, settings


@pytest.fixture
def fake_app_client():
    fastapi_app, repo, gestor, settings = _make_fake_env()
    with TestClient(fastapi_app) as client:
        yield client, repo, gestor, settings


def _resolve_live_mongo_uri() -> Optional[str]:
    explicit = os.getenv("TEST_MONGO_URI") or os.getenv("MONGO_URI")
    candidates = (
        [explicit]
        if explicit
        else ["mongodb://mongodb:27017", "mongodb://127.0.0.1:27018"]
    )
    for candidate in candidates:
        if not candidate:
            continue
        if "127.0.0.1:27017" in candidate or "localhost:27017" in candidate:
            continue
        probe = RepositorioMongoDB(
            uri_conexion=candidate,
            db_name="vi_probe",
            server_selection_timeout_ms=1500,
            connect_timeout_ms=1500,
            socket_timeout_ms=2500,
        )
        ok = probe.ping()
        probe.close()
        if ok:
            return candidate
    return None


@pytest.fixture
def live_app_client():
    uri = _resolve_live_mongo_uri()
    if uri is None:
        if os.getenv("REQUIRE_LIVE_MONGO") == "1":
            pytest.fail(
                "REQUIRE_LIVE_MONGO=1 pero el contenedor Docker mongo:7 no es accesible."
            )
        pytest.skip("Contenedor Docker mongo:7 no accesible para pruebas en vivo.")

    db_name = f"vi_test_{uuid.uuid4().hex[:10]}"
    settings = _make_settings(mongo_uri=uri, mongo_db_name=db_name)
    repo = RepositorioMongoDB(
        uri_conexion=uri,
        db_name=db_name,
        default_username=settings.default_username,
        default_email=settings.default_email,
        default_password=settings.default_password,
        bcrypt_rounds=12,
        server_selection_timeout_ms=3000,
        connect_timeout_ms=3000,
        socket_timeout_ms=5000,
    )
    fastapi_app = create_app(settings=settings, repositorio=repo)
    try:
        with TestClient(fastapi_app) as client:
            yield client, repo, settings
    finally:
        repo._client.drop_database(db_name)
        repo.close()


def _assert_security_headers(response, *, expect_no_store: bool = False) -> None:
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert (
        response.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    )
    assert response.headers.get("Content-Security-Policy") == _EXPECTED_CSP
    if expect_no_store:
        assert response.headers.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# Class 1: CP-01 End-to-End Lifecycle
# ---------------------------------------------------------------------------
class TestUS01CP01Lifecycle:
    def test_lifespan_seeds_vi_account_idempotently(self) -> None:
        fastapi_app, repo, gestor, settings = _make_fake_env()
        with TestClient(fastapi_app):
            user_doc = repo.validarCredencialesUnicas("vi")
            assert user_doc is not None
            assert user_doc["correo"] == "dsceli@espe.edu.ec"
            assert user_doc["password_hash"].startswith("$2b$12$")
            assert bcrypt.checkpw(
                b"OperadorVI2026*", user_doc["password_hash"].encode("utf-8")
            )
            assert user_doc["token_sesion_unica"] == ""
            assert user_doc["codigo_recuperacion"] == ""

            assert repo.actualizarTokenSesionAtomico("vi", "", "keep-me-token") is True

        # Re-entering lifespan simulates app restart and must not overwrite active fields
        fastapi_app_2 = create_app(
            settings=settings, repositorio=repo, gestor=gestor
        )
        with TestClient(fastapi_app_2):
            after = repo.validarCredencialesUnicas("vi")
            assert after is not None
            assert after["token_sesion_unica"] == "keep-me-token"

    def test_cp01_login_success_jwt_and_db_persistence(self, fake_app_client) -> None:
        client, repo, _, settings = fake_app_client
        resp = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert resp.status_code == 200
        _assert_security_headers(resp, expect_no_store=True)
        body = resp.json()
        assert body["usuario"] == "vi"
        assert body["mensaje"] == "Inicio de sesión exitoso."
        token = body["token"]

        decoded = jwt.decode(
            token, settings.jwt_secret, algorithms=[settings.jwt_algorithm]
        )
        assert decoded["sub"] == "vi"
        assert decoded["exp"] > decoded["iat"]
        assert "jti" in decoded

        doc = repo.validarCredencialesUnicas("vi")
        assert doc is not None and doc["token_sesion_unica"] == token

    def test_cp01_wrong_password_and_unknown_user_return_401(
        self, fake_app_client
    ) -> None:
        client, repo, _, _ = fake_app_client
        for creds in (
            {"usuario": "vi", "clave": "ClaveIncorrecta123*"},
            {"usuario": "desconocido", "clave": "OperadorVI2026*"},
        ):
            resp = client.post("/api/auth/login", json=creds)
            assert resp.status_code == 401
            assert resp.json()["detail"] == "Credenciales inválidas o sesión única ya activa."
            _assert_security_headers(resp, expect_no_store=True)

        doc = repo.validarCredencialesUnicas("vi")
        assert doc is not None and doc["token_sesion_unica"] == ""

    def test_cp01_second_login_blocked_while_active_then_allowed_after_logout(
        self, fake_app_client
    ) -> None:
        client, _, _, _ = fake_app_client
        login_1 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert login_1.status_code == 200
        token_1 = login_1.json()["token"]

        login_2 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert login_2.status_code == 401
        assert login_2.json()["detail"] == "Credenciales inválidas o sesión única ya activa."

        verify_1 = client.get(
            "/api/auth/verificar",
            headers={"Authorization": f"Bearer {token_1}"},
        )
        assert verify_1.status_code == 200
        assert verify_1.json() == {"valido": True, "usuario": "vi"}

        logout_resp = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token_1}"},
        )
        assert logout_resp.status_code == 200

        verify_after = client.get(
            "/api/auth/verificar",
            headers={"Authorization": f"Bearer {token_1}"},
        )
        assert verify_after.status_code == 401

        login_3 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert login_3.status_code == 200
        assert login_3.json()["token"] != token_1

    def test_cp01_missing_static_html_routes_return_clean_404_and_health_200(
        self, fake_app_client
    ) -> None:
        client, _, _, _ = fake_app_client
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
        _assert_security_headers(health)

        for route in ("/", "/login", "/recuperar", "/monitoreo"):
            resp = client.get(route)
            assert resp.status_code in (200, 404)
            _assert_security_headers(resp)


# ---------------------------------------------------------------------------
# Class 2: Session Edge Cases & Concurrency
# ---------------------------------------------------------------------------
class TestSessionEdgeCasesAndConcurrency:
    def test_expired_jwt_in_db_is_overwritten_on_login(
        self, fake_app_client
    ) -> None:
        client, repo, _, settings = fake_app_client
        now = datetime.now(timezone.utc)
        expired_jwt = jwt.encode(
            {
                "sub": "vi",
                "iat": now - timedelta(minutes=10),
                "exp": now - timedelta(seconds=60),
                "jti": "expired-jti",
            },
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        assert repo.actualizarTokenSesionAtomico("vi", "", expired_jwt) is True

        resp = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert resp.status_code == 200
        new_token = resp.json()["token"]
        assert new_token != expired_jwt
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == new_token  # type: ignore[index]

    @pytest.mark.parametrize(
        "stored_value",
        [
            "corrupt.jwt.value",
            jwt.encode(
                {
                    "sub": "vi",
                    "iat": datetime.now(timezone.utc),
                    "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
                },
                "wrong-secret-0123456789abcdef0123456789abcdef",
                algorithm="HS256",
            ),
        ],
    )
    def test_corrupt_or_wrong_secret_token_in_db_is_overwritten_on_login(
        self, fake_app_client, stored_value: str
    ) -> None:
        client, repo, _, _ = fake_app_client
        assert repo.actualizarTokenSesionAtomico("vi", "", stored_value) is True

        resp = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert resp.status_code == 200
        new_token = resp.json()["token"]
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == new_token  # type: ignore[index]

    def test_concurrent_login_race_strictly_one_winner(self) -> None:
        fastapi_app, _, gestor, _ = _make_fake_env(bcrypt_rounds=4)
        num_workers = 8
        barrier = threading.Barrier(num_workers)

        with TestClient(fastapi_app) as client:

            def attempt_http(_idx: int):
                barrier.wait(timeout=10)
                return client.post(
                    "/api/auth/login",
                    json={"usuario": "vi", "clave": "OperadorVI2026*"},
                )

            with ThreadPoolExecutor(max_workers=num_workers) as pool:
                responses = list(pool.map(attempt_http, range(num_workers)))

            statuses = [r.status_code for r in responses]
            assert statuses.count(200) == 1
            assert statuses.count(401) == num_workers - 1
            winner_token = next(
                r.json()["token"] for r in responses if r.status_code == 200
            )
            assert (
                client.get(
                    "/api/auth/verificar",
                    headers={"Authorization": f"Bearer {winner_token}"},
                ).status_code
                == 200
            )
            assert gestor.cerrarSesionUnica(winner_token) is True

            # Direct service-level race
            service_barrier = threading.Barrier(num_workers)

            def attempt_service(_idx: int) -> str:
                service_barrier.wait(timeout=10)
                try:
                    gestor.iniciarSesionUnica("vi", "OperadorVI2026*")
                    return "win"
                except SesionActivaError:
                    return "blocked"

            with ThreadPoolExecutor(max_workers=num_workers) as pool:
                outcomes = list(pool.map(attempt_service, range(num_workers)))

            assert outcomes.count("win") == 1
            assert outcomes.count("blocked") == num_workers - 1

    def test_verificar_and_verify_aliases_positive_and_negative(
        self, fake_app_client
    ) -> None:
        client, _, _, settings = fake_app_client
        token = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        ).json()["token"]

        for endpoint in ("/api/auth/verificar", "/api/auth/verify"):
            ok = client.get(endpoint, headers={"Authorization": f"Bearer {token}"})
            assert ok.status_code == 200
            assert ok.json() == {"valido": True, "usuario": "vi"}

        now = datetime.now(timezone.utc)
        expired = jwt.encode(
            {"sub": "vi", "iat": now - timedelta(minutes=5), "exp": now - timedelta(seconds=5)},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        wrong_sub = jwt.encode(
            {"sub": "otro", "iat": now, "exp": now + timedelta(minutes=5)},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        alg_none = jwt.encode(
            {"sub": "vi", "iat": now, "exp": now + timedelta(minutes=5)},
            "",
            algorithm="none",
        )
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")

        bad_headers = [
            {},
            {"Authorization": "Basic dmk6dmk="},
            {"Authorization": "Bearer "},
            {"Authorization": f"Bearer {expired}"},
            {"Authorization": f"Bearer {tampered}"},
            {"Authorization": f"Bearer {alg_none}"},
            {"Authorization": f"Bearer {wrong_sub}"},
        ]
        for hdr in bad_headers:
            for endpoint in ("/api/auth/verificar", "/api/auth/verify"):
                resp = client.get(endpoint, headers=hdr)
                assert resp.status_code == 401
                _assert_security_headers(resp, expect_no_store=True)

        # Stale token after logout + relogin must fail
        assert (
            client.post(
                "/api/auth/logout", headers={"Authorization": f"Bearer {token}"}
            ).status_code
            == 200
        )
        token_2 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        ).json()["token"]
        assert token_2 != token
        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {token}"},
            ).status_code
            == 401
        )

    def test_logout_bearer_header_and_json_body_sendbeacon(
        self, fake_app_client
    ) -> None:
        client, _, _, _ = fake_app_client

        # 1. Bearer header logout
        t1 = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "OperadorVI2026*"}
        ).json()["token"]
        r1 = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {t1}"})
        assert r1.status_code == 200
        assert r1.json() == {"mensaje": "Sesión cerrada correctamente."}
        assert (
            client.post(
                "/api/auth/logout", headers={"Authorization": f"Bearer {t1}"}
            ).status_code
            == 401
        )

        # 2. application/json body only
        t2 = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "OperadorVI2026*"}
        ).json()["token"]
        r2 = client.post("/api/auth/logout", json={"token": t2})
        assert r2.status_code == 200

        # 3. navigator.sendBeacon text/plain;charset=UTF-8 JSON string body
        t3 = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "OperadorVI2026*"}
        ).json()["token"]
        r3 = client.post(
            "/api/auth/logout",
            content=f'{{"token":"{t3}"}}',
            headers={"Content-Type": "text/plain;charset=UTF-8"},
        )
        assert r3.status_code == 200

        # 4. Both Bearer header and JSON body
        t4 = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "OperadorVI2026*"}
        ).json()["token"]
        r4 = client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {t4}"},
            json={"token": t4},
        )
        assert r4.status_code == 200

        # 5. Missing credentials
        assert client.post("/api/auth/logout").status_code == 401

    def test_logout_cross_user_and_wrong_token_rejected_without_clearing_active(
        self, fake_app_client
    ) -> None:
        client, _, _, settings = fake_app_client
        active_token = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "OperadorVI2026*"}
        ).json()["token"]

        now = datetime.now(timezone.utc)
        other_user_jwt = jwt.encode(
            {"sub": "otro_usuario", "iat": now, "exp": now + timedelta(minutes=15)},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        tampered = active_token[:-4] + (
            "AAAA" if not active_token.endswith("AAAA") else "BBBB"
        )

        for bad_token in ("not-a-jwt", tampered, other_user_jwt):
            assert (
                client.post(
                    "/api/auth/logout",
                    headers={"Authorization": f"Bearer {bad_token}"},
                ).status_code
                == 401
            )
            assert (
                client.post("/api/auth/logout", json={"token": bad_token}).status_code
                == 401
            )

        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {active_token}"},
            ).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# Class 3: Two-Step Password Recovery & SMTP
# ---------------------------------------------------------------------------
class TestPasswordRecoveryTwoStepAndSMTP:
    def test_recovery_step1_unregistered_email_returns_404(
        self, fake_app_client
    ) -> None:
        client, repo, _, _ = fake_app_client
        resp = client.post(
            "/api/auth/recuperar",
            json={"accion": "solicitar_codigo", "correo": "noexiste@espe.edu.ec"},
        )
        assert resp.status_code == 404
        assert repo.validarCredencialesUnicas("vi")["codigo_recuperacion"] == ""  # type: ignore[index]

    @pytest.mark.parametrize("smtp_host_val", ["", "   "])
    def test_recovery_step1_smtp_fallback_logs_deterministically(
        self, caplog, capsys, smtp_host_val: str
    ) -> None:
        fastapi_app, repo, _, _ = _make_fake_env(smtp_host=smtp_host_val)
        caplog.set_level(logging.INFO)
        with TestClient(fastapi_app) as client:
            resp = client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            )
        assert resp.status_code == 200
        assert resp.json()["correo"] == "dsceli@espe.edu.ec"

        doc = repo.validarCredencialesUnicas("vi")
        assert doc is not None
        code_in_db = doc["codigo_recuperacion"]
        assert re.fullmatch(r"\d{6}", code_in_db)

        expected_line = f"RECOVERY_CODE correo=dsceli@espe.edu.ec codigo={code_in_db}"
        assert expected_line in caplog.text
        assert expected_line in capsys.readouterr().out

    def test_recovery_step1_smtp_configured_sends_email(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sent_calls: list[dict[str, Any]] = []

        class FakeSMTP:
            def __init__(self, host: str, port: int, timeout: int = 10) -> None:
                self.host = host
                self.port = port
                self.timeout = timeout
                self.events: list[str] = []

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_val, exc_tb) -> None:
                return None

            def ehlo(self) -> None:
                self.events.append("ehlo")

            def starttls(self) -> None:
                self.events.append("starttls")

            def login(self, user: str, password: str) -> None:
                self.events.append(f"login:{user}")

            def send_message(self, msg) -> None:
                sent_calls.append(
                    {
                        "host": self.host,
                        "port": self.port,
                        "events": list(self.events),
                        "to": msg["To"],
                        "from": msg["From"],
                        "body": msg.get_content(),
                    }
                )

        monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
        fastapi_app, repo, _, _ = _make_fake_env(
            smtp_host="smtp.espe.edu.ec",
            smtp_port=587,
            smtp_user="svc-vi@espe.edu.ec",
            smtp_password="smtp-secret-password",
            smtp_from="no-reply@espe.edu.ec",
        )
        with TestClient(fastapi_app) as client:
            resp = client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            )
            assert resp.status_code == 200
            code = repo.validarCredencialesUnicas("vi")["codigo_recuperacion"]  # type: ignore[index]
            assert len(sent_calls) == 1
            assert sent_calls[0]["to"] == "dsceli@espe.edu.ec"
            assert sent_calls[0]["from"] == "no-reply@espe.edu.ec"
            assert "starttls" in sent_calls[0]["events"]
            assert code in sent_calls[0]["body"]

            # SMTP failure returns 502 without leaking password
            class BrokenSMTP(FakeSMTP):
                def login(self, user: str, password: str) -> None:
                    raise smtplib.SMTPAuthenticationError(535, b"Auth failed")

            monkeypatch.setattr(smtplib, "SMTP", BrokenSMTP)
            fail_resp = client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            )
            assert fail_resp.status_code == 502
            assert "smtp-secret-password" not in fail_resp.text

    def test_recovery_step2_wrong_empty_and_replayed_code_rejected(
        self, fake_app_client
    ) -> None:
        client, repo, _, _ = fake_app_client
        original_hash = repo.validarCredencialesUnicas("vi")["password_hash"]  # type: ignore[index]

        # Step 2 before Step 1 (empty code in DB)
        before_resp = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": "123456",
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
            },
        )
        assert before_resp.status_code == 400
        assert repo.validarCredencialesUnicas("vi")["password_hash"] == original_hash  # type: ignore[index]

        # Step 1 issues real code
        assert (
            client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            ).status_code
            == 200
        )
        real_code = repo.validarCredencialesUnicas("vi")["codigo_recuperacion"]  # type: ignore[index]
        wrong_code = "000000" if real_code != "000000" else "999999"

        wrong_resp = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": wrong_code,
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
            },
        )
        assert wrong_resp.status_code == 400
        assert repo.validarCredencialesUnicas("vi")["password_hash"] == original_hash  # type: ignore[index]

        # Consume valid code once
        ok_resp = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": real_code,
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
            },
        )
        assert ok_resp.status_code == 200

        # Replay same code must fail
        replay_resp = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": real_code,
                "nueva_clave": "OtraClaveVI2026*",
                "confirmar_clave": "OtraClaveVI2026*",
            },
        )
        assert replay_resp.status_code == 400

    def test_recovery_step2_mismatched_passwords_rejected(
        self, fake_app_client
    ) -> None:
        client, repo, gestor, _ = fake_app_client
        original_hash = repo.validarCredencialesUnicas("vi")["password_hash"]  # type: ignore[index]
        client.post(
            "/api/auth/recuperar",
            json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
        )
        real_code = repo.validarCredencialesUnicas("vi")["codigo_recuperacion"]  # type: ignore[index]

        mismatch = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": real_code,
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "DiferenteVI2026*",
            },
        )
        assert mismatch.status_code == 400
        assert mismatch.json()["detail"] == "Las contraseñas no coinciden."
        assert repo.validarCredencialesUnicas("vi")["password_hash"] == original_hash  # type: ignore[index]
        assert repo.validarCredencialesUnicas("vi")["codigo_recuperacion"] == real_code  # type: ignore[index]

        with pytest.raises(ContrasenasNoCoincidenError):
            gestor.actualizarContrasena(
                "dsceli@espe.edu.ec", real_code, "NuevaClaveVI2026*", None
            )

        # 3-arg UML compatibility check
        assert (
            gestor.actualizarContrasena(
                "dsceli@espe.edu.ec", real_code, "ClaveUML3Args2026*"
            )
            is True
        )

    def test_recovery_step2_updates_bcrypt12_and_invalidates_active_session(
        self, fake_app_client
    ) -> None:
        client, repo, _, _ = fake_app_client
        token_1 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        ).json()["token"]

        assert (
            client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            ).status_code
            == 200
        )
        code = repo.validarCredencialesUnicas("vi")["codigo_recuperacion"]  # type: ignore[index]

        step2 = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": code,
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
            },
        )
        assert step2.status_code == 200

        updated = repo.validarCredencialesUnicas("vi")
        assert updated is not None
        assert updated["password_hash"].startswith("$2b$12$")
        assert bcrypt.checkpw(
            b"NuevaClaveVI2026*", updated["password_hash"].encode("utf-8")
        )
        assert updated["codigo_recuperacion"] == ""
        assert updated["token_sesion_unica"] == ""

        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {token_1}"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/logout",
                headers={"Authorization": f"Bearer {token_1}"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "OperadorVI2026*"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "NuevaClaveVI2026*"},
            ).status_code
            == 200
        )


# ---------------------------------------------------------------------------
# Class 4: R4 Security Matrix & Headers
# ---------------------------------------------------------------------------
class TestR4SecurityMatrixAndHeaders:
    @pytest.mark.parametrize(
        "bad_val",
        [
            {"$ne": ""},
            {"$gt": ""},
            {"$gte": ""},
            {"$where": "1==1"},
            {"$regex": ".*"},
            {"$or": [{"usuario": "vi"}]},
            ["vi"],
            123,
            True,
            None,
            "$ne",
            "$gt",
            "$where",
            '{"$ne": ""}',
            "' OR 1=1 --",
            "vi' UNION SELECT 1,2,3 --",
            "'; DROP TABLE usuarios;--",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "vi\x00",
            " vi ",
        ],
    )
    def test_r4_login_and_recovery_reject_injection_xss_and_non_scalar(
        self, fake_app_client, bad_val: Any
    ) -> None:
        client, _, _, _ = fake_app_client
        r_login = client.post(
            "/api/auth/login",
            json={"usuario": bad_val, "clave": "OperadorVI2026*"},
        )
        assert r_login.status_code == 422
        assert "<script>" not in r_login.text
        assert "onerror=" not in r_login.text
        assert "javascript:" not in r_login.text
        _assert_security_headers(r_login, expect_no_store=True)

        r_rec1 = client.post(
            "/api/auth/recuperar",
            json={"accion": "solicitar_codigo", "correo": bad_val},
        )
        assert r_rec1.status_code == 422
        assert "<script>" not in r_rec1.text

    @pytest.mark.parametrize(
        "bad_pass",
        [
            {"$ne": ""},
            12345678,
            "$ne",
            "$where",
            '{"$ne": ""}',
            "' OR 1=1 --",
            "admin'--",
            "/*sqli*/",
            "'; DROP TABLE usuarios;--",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "Clave\x00Invalida",
            "Clave\r\nInyectada",
            "        ",
            "a" * 73,
            "ñ" * 37,
        ],
    )
    def test_r4_password_fields_reject_injection_xss_control_and_over_72_bytes(
        self, fake_app_client, bad_pass: Any
    ) -> None:
        client, _, _, _ = fake_app_client
        r_login = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": bad_pass}
        )
        assert r_login.status_code == 422
        assert "<script>" not in r_login.text

        r_step2 = client.post(
            "/api/auth/recuperar",
            json={
                "accion": "actualizar_clave",
                "correo": "dsceli@espe.edu.ec",
                "codigo": "123456",
                "nueva_clave": bad_pass,
                "confirmar_clave": bad_pass,
            },
        )
        assert r_step2.status_code == 422
        assert "<script>" not in r_step2.text

    def test_r4_boundaries_extra_forbid_malformed_json_and_pymongo_error(
        self, fake_app_client
    ) -> None:
        client, repo, _, _ = fake_app_client

        # Exact 72-byte password on login must return 401 (no Bcrypt ValueError 500)
        r_72 = client.post(
            "/api/auth/login", json={"usuario": "vi", "clave": "A" * 72}
        )
        assert r_72.status_code == 401

        # < 8 chars on Step 2 -> 422
        assert (
            client.post(
                "/api/auth/recuperar",
                json={
                    "accion": "actualizar_clave",
                    "correo": "dsceli@espe.edu.ec",
                    "codigo": "123456",
                    "nueva_clave": "Short7!",
                    "confirmar_clave": "Short7!",
                },
            ).status_code
            == 422
        )

        # Unicode digits in codigo -> 422
        assert (
            client.post(
                "/api/auth/recuperar",
                json={
                    "accion": "actualizar_clave",
                    "correo": "dsceli@espe.edu.ec",
                    "codigo": "١٢٣٤٥٦",
                    "nueva_clave": "NuevaClaveVI2026*",
                    "confirmar_clave": "NuevaClaveVI2026*",
                },
            ).status_code
            == 422
        )

        # extra="forbid" across all models
        assert (
            client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "OperadorVI2026*", "extra": 1},
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/auth/logout", json={"token": "abc", "extra": 1}
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/api/auth/recuperar",
                json={
                    "accion": "solicitar_codigo",
                    "correo": "dsceli@espe.edu.ec",
                    "extra": 1,
                },
            ).status_code
            == 422
        )

        # Malformed JSON & method check
        bad_json = client.post(
            "/api/auth/login",
            content=b"{bad",
            headers={"Content-Type": "application/json"},
        )
        assert bad_json.status_code == 422
        assert (
            client.post(
                "/api/auth/logout",
                content=b"{bad",
                headers={"Content-Type": "application/json"},
            ).status_code
            == 422
        )
        assert client.get("/api/auth/login").status_code == 405

        # PyMongoError -> 503 without leaking internals
        def broken_lookup(_usuario: str):
            raise PyMongoError("mongodb://secret-internal-uri:27017 connection lost")

        repo.validarCredencialesUnicas = broken_lookup  # type: ignore[method-assign]
        r_503 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert r_503.status_code == 503
        assert "secret-internal-uri" not in r_503.text
        assert "traceback" not in r_503.text.lower()

        # Verify dependency_overrides compatibility
        fastapi_app = client.app
        assert get_gestor_sesion is not None
        assert fastapi_app.dependency_overrides == {}


# ---------------------------------------------------------------------------
# Class 5: Live Container Integration Tests (REQUIRE_LIVE_MONGO=1)
# ---------------------------------------------------------------------------
class TestUS01LiveContainerIntegration:
    def test_live_cp01_full_lifecycle_and_recovery(self, live_app_client) -> None:
        client, repo, _ = live_app_client

        doc = repo.validarCredencialesUnicas("vi")
        assert doc is not None
        assert doc["password_hash"].startswith("$2b$12$")

        # Login -> 200, second login -> 401
        login_1 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert login_1.status_code == 200
        token_1 = login_1.json()["token"]
        assert (
            client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "OperadorVI2026*"},
            ).status_code
            == 401
        )
        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {token_1}"},
            ).status_code
            == 200
        )

        # Logout -> 200, verificar -> 401
        assert (
            client.post(
                "/api/auth/logout",
                json={"token": token_1},
            ).status_code
            == 200
        )
        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {token_1}"},
            ).status_code
            == 401
        )

        # Login again, then 2-step recovery invalidates live session
        token_2 = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        ).json()["token"]
        assert (
            client.post(
                "/api/auth/recuperar",
                json={"accion": "solicitar_codigo", "correo": "dsceli@espe.edu.ec"},
            ).status_code
            == 200
        )
        code = repo.validarCredencialesUnicas("vi")["codigo_recuperacion"]  # type: ignore[index]
        assert re.fullmatch(r"\d{6}", code)

        assert (
            client.post(
                "/api/auth/recuperar",
                json={
                    "accion": "actualizar_clave",
                    "correo": "dsceli@espe.edu.ec",
                    "codigo": code,
                    "nueva_clave": "LiveClaveVI2026*",
                    "confirmar_clave": "LiveClaveVI2026*",
                },
            ).status_code
            == 200
        )
        assert (
            client.get(
                "/api/auth/verificar",
                headers={"Authorization": f"Bearer {token_2}"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "LiveClaveVI2026*"},
            ).status_code
            == 200
        )

    def test_live_concurrent_barrier_login_race(self, live_app_client) -> None:
        client, _, _ = live_app_client
        num_workers = 8
        barrier = threading.Barrier(num_workers)

        def worker(_idx: int) -> int:
            barrier.wait(timeout=15)
            return client.post(
                "/api/auth/login",
                json={"usuario": "vi", "clave": "OperadorVI2026*"},
            ).status_code

        with ThreadPoolExecutor(max_workers=num_workers) as pool:
            statuses = list(pool.map(worker, range(num_workers)))

        assert statuses.count(200) == 1
        assert statuses.count(401) == num_workers - 1

    def test_live_expired_jwt_overwrite_in_mongodb(self, live_app_client) -> None:
        client, repo, settings = live_app_client
        now = datetime.now(timezone.utc)
        expired_jwt = jwt.encode(
            {"sub": "vi", "iat": now - timedelta(minutes=5), "exp": now - timedelta(seconds=10)},
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm,
        )
        assert repo.actualizarTokenSesionAtomico("vi", "", expired_jwt) is True

        resp = client.post(
            "/api/auth/login",
            json={"usuario": "vi", "clave": "OperadorVI2026*"},
        )
        assert resp.status_code == 200
        new_token = resp.json()["token"]
        assert new_token != expired_jwt
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == new_token  # type: ignore[index]
