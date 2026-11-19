"""Unit and live-container tests for Milestone M1 (app.config & RepositorioMongoDB)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import threading
from typing import Any, Optional
import uuid

import bcrypt
from bson import ObjectId
import pytest
from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError

from app.config import Config, Settings, get_settings
from app.repositories import RepositorioMongoDB


# ---------------------------------------------------------------------------
# Thread-safe in-memory PyMongo fake for deterministic unit tests
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

    def create_index(self, field: str, unique: bool = False, name: Optional[str] = None) -> str:
        idx_name = name or f"{field}_1"
        with self._lock:
            self._indexes[idx_name] = {"key": [(field, 1)], "unique": unique}
        return idx_name

    def index_information(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return deepcopy(self._indexes)

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
                            raise DuplicateKeyError(f"E11000 duplicate key error on {field}")
            self._docs.append(new_doc)
            return _FakeInsertResult(new_doc["_id"])

    def update_one(self, filtro: dict[str, Any], update: dict[str, Any]) -> _FakeUpdateResult:
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


# ---------------------------------------------------------------------------
# Config unit tests
# ---------------------------------------------------------------------------
class TestAppConfig:
    def test_dotenv_parsing_and_env_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_keys = [
            "MONGO_URI",
            "MONGO_DB_NAME",
            "JWT_SECRET",
            "JWT_SECRET_KEY",
            "JWT_ALGORITHM",
            "JWT_EXPIRATION_MINUTES",
            "DEFAULT_USERNAME",
            "DEFAULT_EMAIL",
            "DEFAULT_PASSWORD",
            "BCRYPT_ROUNDS",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USER",
            "SMTP_PASSWORD",
            "SMTP_FROM",
            "APP_PORT",
            "LOG_LEVEL",
        ]
        for key in env_keys:
            monkeypatch.delenv(key, raising=False)

        env_file = tmp_path / ".env"
        env_file.write_text(
            "\n".join(
                [
                    "# Comment line",
                    "MONGO_URI=mongodb://custom-host:27017 # inline comment",
                    'export DEFAULT_PASSWORD="Pass#WithHash"',
                    "SMTP_HOST=",
                    "JWT_SECRET=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "LOG_LEVEL=debug",
                ]
            ),
            encoding="utf-8",
        )
        # Existing OS env var must win over .env
        monkeypatch.setenv("MONGO_DB_NAME", "vi_override_db")

        settings = get_settings(env_path=env_file)
        assert Config is Settings
        assert settings.mongo_uri == "mongodb://custom-host:27017"
        assert settings.MONGO_URI == "mongodb://custom-host:27017"
        assert settings.mongo_db_name == "vi_override_db"
        assert settings.default_password == "Pass#WithHash"
        assert settings.smtp_host == ""
        assert settings.log_level == "DEBUG"
        assert settings.bcrypt_rounds == 12
        settings.validate_jwt_secret()

    def test_missing_dotenv_uses_safe_defaults_and_validates_jwt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for key in ("MONGO_URI", "JWT_SECRET", "JWT_SECRET_KEY", "BCRYPT_ROUNDS"):
            monkeypatch.delenv(key, raising=False)

        settings = Settings.from_env(env_path=tmp_path / "nonexistent.env")
        assert settings.DEFAULT_USERNAME == "vi"
        assert settings.DEFAULT_EMAIL == "dsceli@espe.edu.ec"
        assert settings.SMTP_FROM == "no-reply@espe.edu.ec"
        assert settings.JWT_EXPIRATION_MINUTES == 480
        with pytest.raises(ValueError, match="JWT_SECRET"):
            settings.validate_jwt_secret()

        monkeypatch.setenv("JWT_SECRET", "CAMBIAR_POR_SECRETO_ALEATORIO_SEGURO_MIN_32_CHARS")
        with pytest.raises(ValueError, match="JWT_SECRET"):
            get_settings(env_path=tmp_path / "nonexistent.env").validate_jwt_secret()

    def test_invalid_integer_env_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BCRYPT_ROUNDS", "not-an-int")
        with pytest.raises(ValueError, match="BCRYPT_ROUNDS"):
            get_settings(env_path=tmp_path / "nonexistent.env")

        monkeypatch.setenv("BCRYPT_ROUNDS", "99")
        with pytest.raises(ValueError, match="BCRYPT_ROUNDS"):
            get_settings(env_path=tmp_path / "nonexistent.env")


# ---------------------------------------------------------------------------
# Pure Unit Tests (always run, zero external DB required)
# ---------------------------------------------------------------------------
class TestRepositorioMongoDBUnit:
    def _make_repo(self, **kwargs: Any) -> tuple[RepositorioMongoDB, _FakeMongoClient]:
        fake_client = _FakeMongoClient()
        defaults = {
            "uri_conexion": "mongodb://mongodb:27017",
            "db_name": "vi_unit_db",
            "default_username": "vi",
            "default_email": "dsceli@espe.edu.ec",
            "default_password": "OperadorVI2026*",
            "bcrypt_rounds": 12,
            "client": fake_client,
        }
        defaults.update(kwargs)
        repo = RepositorioMongoDB(**defaults)
        return repo, fake_client

    def test_figura4_attributes_and_context_manager(self) -> None:
        repo, fake_client = self._make_repo()
        with repo as ctx:
            assert ctx.uriConexion == "mongodb://mongodb:27017"
            assert ctx.colUsuarios is not None
            assert ctx.colAlertas is not None
            assert ctx.colEvaluaciones is not None
            assert ctx.ping() is True
            assert ctx.esperar_conexion(max_retries=2, delay_seconds=0.0) is True
        assert fake_client.closed is True

    def test_inicializar_cuenta_unica_seeds_bcrypt_12_rounds(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        user_doc = repo.validarCredencialesUnicas("vi")
        assert user_doc is not None
        assert user_doc["usuario"] == "vi"
        assert user_doc["correo"] == "dsceli@espe.edu.ec"
        assert user_doc["token_sesion_unica"] == ""
        assert user_doc["codigo_recuperacion"] == ""
        assert "password" not in user_doc
        assert "clave" not in user_doc
        assert user_doc["password_hash"].startswith("$2b$12$")
        assert bcrypt.checkpw(b"OperadorVI2026*", user_doc["password_hash"].encode("utf-8"))

        indexes = repo.colUsuarios.index_information()
        assert indexes["idx_usuario_unique"]["unique"] is True
        assert indexes["idx_correo_unique"]["unique"] is True

    def test_inicializar_cuenta_unica_is_idempotent_on_restart(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        custom_hash = bcrypt.hashpw(b"NuevaClave2026*", bcrypt.gensalt(rounds=4)).decode("utf-8")
        assert repo.actualizarTokenSesionUnica("vi", "jwt-active-123") is True
        assert repo.guardarCodigoRecuperacion("dsceli@espe.edu.ec", "654321") is True
        assert repo.colUsuarios.update_one(
            {"usuario": "vi"}, {"$set": {"password_hash": custom_hash}}
        ).matched_count == 1

        # Re-run initialization (simulating container restart)
        repo.inicializarCuentaUnica()

        after = repo.validarCredencialesUnicas("vi")
        assert after is not None
        assert after["password_hash"] == custom_hash
        assert after["token_sesion_unica"] == "jwt-active-123"
        assert after["codigo_recuperacion"] == "654321"

    def test_inicializar_cuenta_unica_handles_duplicate_key_race(self) -> None:
        repo, _ = self._make_repo()
        original_insert = repo.colUsuarios.insert_one

        def racing_insert(doc: dict[str, Any]) -> Any:
            original_insert(doc)
            raise DuplicateKeyError("Simulated concurrent seed insert")

        repo.colUsuarios.insert_one = racing_insert  # type: ignore[method-assign]
        repo.inicializarCuentaUnica()
        assert repo.validarCredencialesUnicas("vi") is not None

    def test_inicializar_cuenta_unica_rejects_over_72_byte_password(self) -> None:
        repo_ascii, _ = self._make_repo(default_password="a" * 73)
        with pytest.raises(ValueError, match="72 bytes"):
            repo_ascii.inicializarCuentaUnica()

        repo_utf8, _ = self._make_repo(default_password="á" * 37)  # 74 UTF-8 bytes
        with pytest.raises(ValueError, match="72 bytes"):
            repo_utf8.inicializarCuentaUnica()

    def test_validar_credenciales_y_correo_and_nosqli_type_guards(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        assert repo.validarCredencialesUnicas("") is None
        assert repo.validarCredencialesUnicas("desconocido") is None
        assert repo.obtenerUsuarioPorCorreo("") is None
        assert repo.obtenerUsuarioPorCorreo("noexiste@espe.edu.ec") is None
        found = repo.obtenerUsuarioPorCorreo("dsceli@espe.edu.ec")
        assert found is not None and found["usuario"] == "vi"

        bad_inputs: list[Any] = [{"$ne": ""}, {"$gt": ""}, ["vi"], 123, None, "vi\x00", "$where"]
        for bad in bad_inputs:
            with pytest.raises(ValueError):
                repo.validarCredencialesUnicas(bad)
            with pytest.raises(ValueError):
                repo.obtenerUsuarioPorCorreo(bad)
            with pytest.raises(ValueError):
                repo.actualizarTokenSesionUnica(bad, "tok")
            with pytest.raises(ValueError):
                repo.guardarCodigoRecuperacion(bad, "123456")
            with pytest.raises(ValueError):
                repo.actualizarPasswordHash(bad, "$2b$12$fakehash")

        with pytest.raises(ValueError):
            repo.consultarAlertas("$ne")
        with pytest.raises(ValueError):
            repo.consultarAlertas({"$ne": ""}  # type: ignore[arg-type]
            )

    def test_actualizar_token_sesion_unica_matched_count(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        assert repo.actualizarTokenSesionUnica("vi", "jwt-1") is True
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == "jwt-1"  # type: ignore[index]
        assert repo.actualizarTokenSesionUnica("vi", "") is True
        # Clearing again when already empty still matches 1 doc -> True
        assert repo.actualizarTokenSesionUnica("vi", "") is True
        assert repo.actualizarTokenSesionUnica("inexistente", "jwt-1") is False

    def test_actualizar_token_sesion_atomico_transitions_and_concurrency(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        # Empty -> active succeeds
        assert repo.actualizarTokenSesionAtomico("vi", "", "jwt-active") is True
        # Competing empty -> active fails while session active
        assert repo.actualizarTokenSesionAtomico("vi", "", "jwt-competing") is False
        assert repo.actualizarTokenSesionAtomico("vi", None, "jwt-competing") is False
        # Replacing specific expired token succeeds
        assert repo.actualizarTokenSesionAtomico("vi", "jwt-active", "jwt-refreshed") is True
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == "jwt-refreshed"  # type: ignore[index]

        # Simulate document with None / missing token_sesion_unica
        repo.colUsuarios.update_one({"usuario": "vi"}, {"$set": {"token_sesion_unica": None}})
        assert repo.actualizarTokenSesionAtomico("vi", None, "jwt-from-none") is True

        # Reset and race 8 concurrent threads
        assert repo.actualizarTokenSesionUnica("vi", "") is True
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda idx: repo.actualizarTokenSesionAtomico("vi", "", f"jwt-race-{idx}"),
                    range(8),
                )
            )
        assert sum(1 for ok in results if ok) == 1

    def test_limpiar_token_si_coincide(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        assert repo.actualizarTokenSesionAtomico("vi", "", "jwt-live") is True
        assert repo.limpiarTokenSiCoincide("vi", "") is False
        assert repo.limpiarTokenSiCoincide("vi", "jwt-wrong") is False
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == "jwt-live"  # type: ignore[index]

        assert repo.limpiarTokenSiCoincide("vi", "jwt-live") is True
        assert repo.validarCredencialesUnicas("vi")["token_sesion_unica"] == ""  # type: ignore[index]

    def test_recuperacion_codigo_y_actualizar_password_hash(self) -> None:
        repo, _ = self._make_repo()
        repo.inicializarCuentaUnica()

        assert repo.actualizarTokenSesionAtomico("vi", "", "jwt-session") is True
        assert repo.guardarCodigoRecuperacion("dsceli@espe.edu.ec", "482910") is True
        doc = repo.obtenerUsuarioPorCorreo("dsceli@espe.edu.ec")
        assert doc is not None and doc["codigo_recuperacion"] == "482910"

        new_hash = bcrypt.hashpw(b"NuevaClaveSegura2026*", bcrypt.gensalt(rounds=4)).decode("utf-8")
        assert repo.actualizarPasswordHash("dsceli@espe.edu.ec", new_hash) is True

        updated = repo.obtenerUsuarioPorCorreo("dsceli@espe.edu.ec")
        assert updated is not None
        assert updated["password_hash"] == new_hash
        assert updated["codigo_recuperacion"] == ""
        assert updated["token_sesion_unica"] == ""
        assert repo.actualizarPasswordHash("otro@espe.edu.ec", new_hash) is False

    def test_figura4_alertas_y_evaluaciones_crud(self) -> None:
        repo, _ = self._make_repo()
        t_old = datetime.now(timezone.utc) - timedelta(minutes=5)
        t_new = datetime.now(timezone.utc)

        id1 = repo.guardarAlertaAutomatica(
            {
                "track_id": 1,
                "motivo_alerta": "Permanencia",
                "tiempo_estancia_seg": 18.5,
                "captura_jpg": "cap_1.jpg",
                "fecha_evento": t_old,
            }
        )
        id2 = repo.guardarAlertaAutomatica(
            {
                "track_id": 2,
                "motivo_alerta": "Postura Sospechosa",
                "tiempo_estancia_seg": 7.0,
                "captura_jpg": "cap_2.jpg",
                "fecha_evento": t_new,
            }
        )
        id3 = repo.guardarAlertaAutomatica(
            {
                "track_id": 3,
                "motivo_alerta": "Permanencia",
                "tiempo_estancia_seg": 22.0,
                "captura_jpg": "cap_3.jpg",
            }
        )
        assert isinstance(id1, ObjectId)
        assert isinstance(id2, ObjectId)
        assert isinstance(id3, ObjectId)

        all_alerts = repo.consultarAlertas()
        assert [a["track_id"] for a in all_alerts] == [3, 2, 1]

        filtered = repo.consultarAlertas("Permanencia")
        assert [a["track_id"] for a in filtered] == [3, 1]
        filtered_kw = repo.consultarAlertas(filtroMotivo="Postura Sospechosa")
        assert [a["track_id"] for a in filtered_kw] == [2]

        eval_id = repo.guardarEvaluacionAutomatica(
            {
                "nombre_video": "demo.mp4",
                "porcentaje_area_cerco": 35.2,
                "fps_con_cerco": 28.4,
                "fps_escena_completa": 16.1,
            }
        )
        assert isinstance(eval_id, ObjectId)
        stored_eval = repo.colEvaluaciones.find_one({"_id": eval_id})
        assert stored_eval is not None and "fecha_evaluacion" in stored_eval

        with pytest.raises(ValueError, match="\\$"):
            repo.guardarAlertaAutomatica({"$where": "true"})
        with pytest.raises(ValueError, match="\\$"):
            repo.guardarEvaluacionAutomatica({"nested": {"$ne": 1}})


# ---------------------------------------------------------------------------
# Live Docker mongo:7 Container Integration Tests
# ---------------------------------------------------------------------------
def _resolve_live_mongo_uri() -> Optional[str]:
    explicit = os.getenv("TEST_MONGO_URI") or os.getenv("MONGO_URI")
    candidates = [explicit] if explicit else ["mongodb://mongodb:27017", "mongodb://127.0.0.1:27018"]
    for candidate in candidates:
        if not candidate:
            continue
        # Never accidentally connect to host native Windows mongod on 27017
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
def live_repo() -> RepositorioMongoDB:
    uri = _resolve_live_mongo_uri()
    if uri is None:
        if os.getenv("REQUIRE_LIVE_MONGO") == "1":
            pytest.fail(
                "REQUIRE_LIVE_MONGO=1 pero el contenedor Docker mongo:7 no es accesible en mongodb:27017 ni 127.0.0.1:27018."
            )
        pytest.skip("Contenedor Docker mongo:7 no accesible para pruebas en vivo.")

    db_name = f"vi_test_{uuid.uuid4().hex[:10]}"
    repo = RepositorioMongoDB(
        uri_conexion=uri,
        db_name=db_name,
        default_username="vi",
        default_email="dsceli@espe.edu.ec",
        default_password="OperadorVI2026*",
        bcrypt_rounds=12,
        server_selection_timeout_ms=3000,
        connect_timeout_ms=3000,
        socket_timeout_ms=5000,
    )
    try:
        assert repo.ping() is True
        yield repo
    finally:
        repo._client.drop_database(db_name)
        repo.close()


class TestRepositorioMongoDBLiveContainer:
    def test_live_seed_indexes_and_idempotency(self, live_repo: RepositorioMongoDB) -> None:
        live_repo.inicializarCuentaUnica()
        doc = live_repo.validarCredencialesUnicas("vi")
        assert doc is not None
        assert doc["usuario"] == "vi"
        assert doc["correo"] == "dsceli@espe.edu.ec"
        assert doc["token_sesion_unica"] == ""
        assert doc["codigo_recuperacion"] == ""
        assert doc["password_hash"].startswith("$2b$12$")
        assert bcrypt.checkpw(b"OperadorVI2026*", doc["password_hash"].encode("utf-8"))

        indexes = live_repo.colUsuarios.index_information()
        assert indexes["idx_usuario_unique"]["unique"] is True
        assert indexes["idx_correo_unique"]["unique"] is True

        # Mutate and verify restart idempotency
        assert live_repo.actualizarTokenSesionAtomico("vi", "", "jwt-live-keep") is True
        live_repo.inicializarCuentaUnica()
        doc_after = live_repo.validarCredencialesUnicas("vi")
        assert doc_after is not None and doc_after["token_sesion_unica"] == "jwt-live-keep"

    def test_live_concurrent_atomic_session_lock(self, live_repo: RepositorioMongoDB) -> None:
        live_repo.inicializarCuentaUnica()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(
                    lambda idx: live_repo.actualizarTokenSesionAtomico("vi", "", f"jwt-live-{idx}"),
                    range(8),
                )
            )
        assert sum(1 for ok in results if ok) == 1

    def test_live_logout_and_password_reset_clears_session_and_code(
        self, live_repo: RepositorioMongoDB
    ) -> None:
        live_repo.inicializarCuentaUnica()
        assert live_repo.actualizarTokenSesionAtomico("vi", "", "jwt-session-1") is True
        assert live_repo.limpiarTokenSiCoincide("vi", "jwt-wrong") is False
        assert live_repo.limpiarTokenSiCoincide("vi", "jwt-session-1") is True

        assert live_repo.actualizarTokenSesionAtomico("vi", "", "jwt-session-2") is True
        assert live_repo.guardarCodigoRecuperacion("dsceli@espe.edu.ec", "901234") is True

        new_hash = bcrypt.hashpw(b"ClaveActualizada2026*", bcrypt.gensalt(rounds=12)).decode("utf-8")
        assert live_repo.actualizarPasswordHash("dsceli@espe.edu.ec", new_hash) is True

        updated = live_repo.obtenerUsuarioPorCorreo("dsceli@espe.edu.ec")
        assert updated is not None
        assert updated["password_hash"] == new_hash
        assert updated["codigo_recuperacion"] == ""
        assert updated["token_sesion_unica"] == ""

    def test_live_alertas_y_evaluaciones_persistence(self, live_repo: RepositorioMongoDB) -> None:
        older = datetime.now(timezone.utc) - timedelta(seconds=30)
        newer = datetime.now(timezone.utc)

        a1 = live_repo.guardarAlertaAutomatica(
            {
                "track_id": 10,
                "motivo_alerta": "Permanencia",
                "tiempo_estancia_seg": 15.0,
                "captura_jpg": "a1.jpg",
                "fecha_evento": older,
            }
        )
        a2 = live_repo.guardarAlertaAutomatica(
            {
                "track_id": 11,
                "motivo_alerta": "Objeto Abandonado",
                "tiempo_estancia_seg": 25.0,
                "captura_jpg": "a2.jpg",
                "fecha_evento": newer,
            }
        )
        assert isinstance(a1, ObjectId) and isinstance(a2, ObjectId)

        alerts = live_repo.consultarAlertas()
        assert [a["track_id"] for a in alerts] == [11, 10]
        assert [a["track_id"] for a in live_repo.consultarAlertas("Permanencia")] == [10]

        ev_id = live_repo.guardarEvaluacionAutomatica(
            {
                "nombre_video": "campus_test.mp4",
                "porcentaje_area_cerco": 40.0,
                "fps_con_cerco": 30.0,
                "fps_escena_completa": 18.0,
            }
        )
        assert isinstance(ev_id, ObjectId)
        assert live_repo.colEvaluaciones.find_one({"_id": ev_id}) is not None
