"""Tier 4: Real-World Multi-Step Operator Workload E2E tests (6 scenarios)."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import tempfile
import time

import pytest

from conftest import (
    DockerInspector,
    E2EConfig,
    VIHttpClient,
    b64url_encode,
    decode_jwt_payload_unverified,
    discover_and_fetch_page_bundle,
    extract_css_custom_properties,
    find_optional_browser_and_node,
    resolve_css_vars,
    strip_css_comments,
    strip_js_comments,
)


def test_t4_workload_cp01_complete_operator_shift_lifecycle(
    client: VIHttpClient, config: E2EConfig
) -> None:
    """Scenario 1: CP-01 complete operator shift, concurrent lock, logout, and handoff."""
    # 1. Seed operator logs in
    login_resp = client.login(config.username, config.password)
    assert login_resp.status_code == 200
    login_data = login_resp.json()
    jwt1 = login_data["token"]
    assert login_data["usuario"] == config.username

    # 2. Verify JWT structure (opaque decode) & active session check
    header, payload = decode_jwt_payload_unverified(jwt1)
    assert header.get("alg") == "HS256"
    assert (
        payload.get("sub") == config.username
        or payload.get("usuario") == config.username
    )
    assert isinstance(payload.get("exp"), (int, float))
    if "iat" in payload:
        assert payload["exp"] > payload["iat"]
    else:
        assert payload["exp"] > time.time()

    verify1 = client.verificar(jwt1)
    assert verify1.status_code == 200
    v1_data = verify1.json()
    assert v1_data.get("valido") is True and v1_data.get("usuario") == config.username

    # 3. Concurrent login attempt must be rejected with 401 while shift is active
    intruder = client.login(config.username, config.password)
    assert intruder.status_code == 401
    assert "Credenciales inválidas o sesión única ya activa." in intruder.json().get(
        "detail", ""
    )

    # Active session remains unaffected
    assert client.verificar(jwt1).status_code == 200

    # 4. Operator ends shift cleanly via POST /api/auth/logout
    logout_resp = client.logout(jwt1)
    assert logout_resp.status_code == 200
    assert client.verificar(jwt1).status_code == 401

    # 5. Next operator shift logs in cleanly with a fresh JWT
    time.sleep(1.05)
    relogin = client.login(config.username, config.password)
    assert relogin.status_code == 200
    jwt2 = relogin.json()["token"]
    assert jwt2 != jwt1
    assert client.verificar(jwt2).status_code == 200
    assert client.logout(jwt2).status_code == 200


def test_t4_workload_forgotten_password_and_session_eviction(
    auth_session: tuple[VIHttpClient, str],
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    """Scenario 2: Full forgotten password recovery, session eviction, and seed restore."""
    client, dangling_jwt = auth_session
    assert client.verificar(dangling_jwt).status_code == 200

    # 1. Request Step 1 recovery OTP
    baseline = log_baseline(config.email)
    step1 = client.recuperar_solicitar(config.email)
    assert step1.status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)
    assert re.fullmatch(r"\d{6}", otp)

    # 2. Wrong OTP and mismatched confirmation must fail without clearing password
    wrong_otp = "000000" if otp != "000000" else "999999"
    assert (
        client.recuperar_actualizar(
            config.email, wrong_otp, "OperadorVI_Rotated2026*", "OperadorVI_Rotated2026*"
        ).status_code
        in (400, 401)
    )
    assert (
        client.recuperar_actualizar(
            config.email, otp, "OperadorVI_Rotated2026*", "MismatchVI2026*"
        ).status_code
        in (400, 401, 422)
    )

    # 3. Valid Step 2 updates password and evicts dangling_jwt
    rotated = "OperadorVI_Rotated2026*"
    step2 = client.recuperar_actualizar(config.email, otp, rotated, rotated)
    assert step2.status_code == 200

    assert client.verificar(dangling_jwt).status_code == 401
    # Replaying the same OTP must be rejected
    assert (
        client.recuperar_actualizar(
            config.email, otp, "AnotherVI2026*", "AnotherVI2026*"
        ).status_code
        in (400, 401)
    )

    # 4. Login with rotated password succeeds, old password rejected
    assert client.login(config.username, config.password).status_code == 401
    rotated_login = client.login(config.username, rotated)
    assert rotated_login.status_code == 200
    assert client.logout(rotated_login.json()["token"]).status_code == 200

    # 5. Restore original seed password via second Step 1 -> Step 2 cycle
    baseline_restore = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    restore_otp = otp_extractor(config.email, baseline=baseline_restore)
    assert (
        client.recuperar_actualizar(
            config.email, restore_otp, config.password, config.password
        ).status_code
        == 200
    )
    restored_login = client.login(config.username, config.password)
    assert restored_login.status_code == 200
    assert client.logout(restored_login.json()["token"]).status_code == 200


def test_t4_workload_tab_close_sendbeacon_unload_recovery(
    client: VIHttpClient, config: E2EConfig
) -> None:
    """Scenario 3: Tab-close sendBeacon/keepalive JSON-body logout and immediate relogin."""
    login1 = client.login(config.username, config.password)
    assert login1.status_code == 200
    jwt1 = login1.json()["token"]
    assert client.verificar(jwt1).status_code == 200

    # Simulate navigator.sendBeacon / fetch(keepalive) with JSON body only, no Auth header
    beacon_resp = client.logout(jwt1, via_body=True)
    assert beacon_resp.status_code == 200
    assert client.verificar(jwt1).status_code == 401

    # Re-opening browser tab allows immediate new login
    login2 = client.login(config.username, config.password)
    assert login2.status_code == 200
    jwt2 = login2.json()["token"]
    assert client.verificar(jwt2).status_code == 200
    assert client.logout(jwt2).status_code == 200


def test_t4_workload_multi_vector_attack_storm_during_active_shift(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    """Scenario 4: Multi-vector NoSQLi/SQLi/XSS/JWT attack storm leaves active shift intact."""
    client, jwt1 = auth_session

    attack_calls = [
        # NoSQLi nested dict operators
        lambda: client.post_json(
            "/api/auth/login", {"usuario": {"$ne": ""}, "clave": {"$gt": ""}}
        ),
        lambda: client.post_json(
            "/api/auth/login", {"usuario": {"$where": "sleep(1000)"}, "clave": "x"}
        ),
        lambda: client.post_json(
            "/api/auth/login",
            {"usuario": {"$or": [{"usuario": "vi"}]}, "clave": {"$regex": ".*"}},
        ),
        lambda: client.post_json(
            "/api/auth/recuperar",
            {"accion": "solicitar_codigo", "correo": {"$gte": ""}},
        ),
        lambda: client.post_json("/api/auth/logout", {"token": {"$ne": ""}}),
        # Embedded NoSQLi / SQLi / XSS / null bytes
        lambda: client.login("' OR 1=1 --", "x"),
        lambda: client.login("vi' UNION SELECT 1,2,3 --", "x"),
        lambda: client.login("'; DROP TABLE usuarios;--", "x"),
        lambda: client.login("<script>alert(1)</script>", "<img src=x onerror=alert(1)>"),
        lambda: client.login("vi\x00", "OperadorVI2026*\x00"),
        lambda: client.recuperar_solicitar("javascript:alert(1)"),
        lambda: client.recuperar_actualizar(
            config.email, "123456", "<script>alert(1)</script>", "<script>alert(1)</script>"
        ),
        # >72-byte ASCII and multi-byte UTF-8 Bcrypt caps
        lambda: client.login(config.username, "A" * 73),
        lambda: client.login(config.username, "ñ" * 37),
        # Extra JSON fields
        lambda: client.post_json(
            "/api/auth/login",
            {"usuario": config.username, "clave": config.password, "role": "admin"},
        ),
        # JWT tampering (alg=none + signature flip)
        lambda: client.verificar(
            f"{b64url_encode(b'{\"alg\":\"none\",\"typ\":\"JWT\"}')}.{jwt1.split('.')[1]}."
        ),
        lambda: client.verificar(
            jwt1[:-1] + ("A" if jwt1[-1] != "A" else "B")
        ),
    ]

    for execute_attack in attack_calls:
        resp = execute_attack()
        assert 400 <= resp.status_code < 500, (
            f"Attack payload produced unexpected status {resp.status_code}: {resp.text}"
        )
        assert resp.headers.get("x-content-type-options", "").lower() == "nosniff"
        lowered = resp.text.lower()
        assert "traceback" not in lowered
        assert 'file "/app' not in lowered
        assert "<script>" not in lowered

    # Active operator session remained uncorrupted throughout the storm
    assert client.verificar(jwt1).status_code == 200
    assert client.logout(jwt1).status_code == 200


def test_t4_complete_served_ui_and_design_audit_across_pantallas(
    client: VIHttpClient, config: E2EConfig
) -> None:
    """Scenario 5: Full opaque-box served UI, DESIGN.md, CSP, and optional browser/Node audit."""
    all_css: dict[str, str] = {}
    all_js: dict[str, str] = {}
    bundles: dict[str, dict] = {}

    for route in ("/", "/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        bundles[route] = bundle
        insp = bundle["inspector"]
        headers = bundle["page"].headers

        assert headers.get("x-content-type-options", "").lower() == "nosniff"
        csp = headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert not bundle["external_urls"]
        assert not insp.inline_scripts
        assert not insp.inline_styles
        assert not insp.inline_event_attrs
        assert "MongoDB Atlas" not in bundle["page"].text
        assert "RepositorioMongoDBAtlas" not in bundle["page"].text

        for url, resp in bundle["css"].items():
            assert resp.status_code == 200
            assert "MongoDB Atlas" not in resp.text
            all_css[url] = strip_css_comments(resp.text)
        for url, resp in bundle["js"].items():
            assert resp.status_code == 200
            assert "MongoDB Atlas" not in resp.text
            all_js[url] = strip_js_comments(resp.text)

    combined_css = "\n".join(all_css.values()).lower()
    css_props = extract_css_custom_properties(combined_css)
    for token in ("#f7f7f4", "#ffffff", "#26251e", "#f54e00", "#1f8a65", "#cf2d56"):
        assert token in combined_css
    for match in re.finditer(r"box-shadow\s*:\s*([^;}{]+)", combined_css):
        raw_val = match.group(1).replace("!important", "").strip()
        val = resolve_css_vars(raw_val, css_props)
        assert val in ("none", "0", "0px")
    for pastel in ("#dfa88f", "#9fc9a2", "#9fbbe0", "#c0a8dd", "#c08532"):
        assert pastel not in combined_css
    assert "@media" in combined_css
    assert re.search(r"1px\s+solid", combined_css)
    resolved_weights = [
        resolve_css_vars(val, css_props)
        for val in re.findall(r"font-weight\s*:\s*([^;}{]+)", combined_css)
    ]
    assert any(re.search(r"\b400\b", w) for w in resolved_weights)

    combined_js = "\n".join(all_js.values())
    assert "sessionStorage" in combined_js
    assert "vi_jwt_token" in combined_js
    assert "/api/auth/verificar" in combined_js
    assert re.search(r"pagehide|beforeunload", combined_js)
    for forbidden in ("localStorage", ".innerHTML", ".outerHTML", ".insertAdjacentHTML", "document.write"):
        assert forbidden not in combined_js

    # Wireframe spot checks across Pantallas 1-3
    assert "INICIAR SESIÓN" in bundles["/login"]["inspector"].visible_text.upper()
    assert "1. Verificar correo" in bundles["/recuperar"]["inspector"].visible_text
    assert "CÁMARA EN TIEMPO REAL" in bundles["/monitoreo"]["inspector"].visible_text

    # Additive Node syntax check and headless browser DOM audit (zero skips in container)
    tools = find_optional_browser_and_node(config)
    if tools["node"]:
        with tempfile.TemporaryDirectory() as tmpdir:
            for idx, (url, js_resp) in enumerate(
                [
                    (u, r)
                    for b in bundles.values()
                    for u, r in b["js"].items()
                ]
            ):
                tmp_js = Path(tmpdir) / f"asset_{idx}.js"
                tmp_js.write_text(js_resp.text, encoding="utf-8")
                proc = subprocess.run(
                    [tools["node"], "--check", str(tmp_js)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                assert proc.returncode == 0, (
                    f"node --check failed for {url}: {proc.stderr}"
                )

    if tools["browser"]:
        def _dump_dom(target_url: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory() as user_data_dir:
                return subprocess.run(
                    [
                        tools["browser"],  # type: ignore[list-item]
                        "--headless",
                        "--dump-dom",
                        "--disable-gpu",
                        "--no-first-run",
                        f"--user-data-dir={user_data_dir}",
                        "--virtual-time-budget=3000",
                        target_url,
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=15,
                    check=False,
                )

        login_dom = _dump_dom(f"{config.base_url}/login")
        assert login_dom.returncode == 0, (
            f"Headless browser check failed (rc={login_dom.returncode}): {login_dom.stderr}"
        )
        assert "BIENVENIDO" in login_dom.stdout.upper()
        assert "INICIAR SESIÓN" in login_dom.stdout.upper()

        rec_dom = _dump_dom(f"{config.base_url}/recuperar")
        assert rec_dom.returncode == 0
        assert "RECUPERAR CONTRASEÑA" in rec_dom.stdout.upper()
        assert "1. Verificar correo" in rec_dom.stdout

        # Unauthenticated /monitoreo in fresh profile must redirect to /login
        mon_dom = _dump_dom(f"{config.base_url}/monitoreo")
        assert mon_dom.returncode == 0
        assert "BIENVENIDO" in mon_dom.stdout.upper()
        assert "INICIAR SESIÓN" in mon_dom.stdout.upper()


def test_t4_workload_deployment_readiness_and_static_surface_audit(
    client: VIHttpClient, config: E2EConfig, docker_inspector: DockerInspector
) -> None:
    """Scenario 6: Deployment readiness, seed idempotency, local MongoDB, zero Atlas."""
    for route in ("/", "/login", "/recuperar", "/monitoreo", "/static/css/styles.css"):
        resp = client.get(route)
        assert resp.status_code == 200
        assert "MongoDB Atlas" not in resp.text
        assert "RepositorioMongoDBAtlas" not in resp.text

    # Seed auth & recovery work cleanly
    login = client.login(config.username, config.password)
    assert login.status_code == 200
    tok = login.json()["token"]
    assert client.verificar(tok).status_code == 200
    assert client.logout(tok).status_code == 200

    assert client.recuperar_solicitar(config.email).status_code == 200

    docs = docker_inspector.query_usuarios_via_mongosh()
    if (
        docker_inspector.enabled
        and docker_inspector.cli_available
        and docker_inspector.compose_file_path.exists()
    ):
        assert docs is not None, (
            "Docker CLI and docker-compose.yml are available (VI_DOCKER_CHECKS=1), "
            "but query_usuarios_via_mongosh() returned None."
        )
    if docs is not None:
        seed_docs = [d for d in docs if d.get("usuario") == config.username]
        assert len(seed_docs) == 1
        assert seed_docs[0].get("correo") == config.email
        assert "password" not in seed_docs[0]
        assert re.match(r"^\$2[aby]\$12\$", seed_docs[0].get("password_hash", ""))
        assert seed_docs[0].get("token_sesion_unica", "") == ""
