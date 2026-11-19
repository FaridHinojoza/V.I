"""Tier 3: Cross-Feature Pairwise Combination E2E tests (15 tests across F1-F8)."""

from __future__ import annotations

import re

from conftest import (
    E2EConfig,
    VIHttpClient,
    discover_and_fetch_page_bundle,
    strip_js_comments,
)


# ---------------------------------------------------------------------------
# Pairwise Backend & Security Combinations (F1-F6, F8) — 10 tests
# ---------------------------------------------------------------------------


def test_t3_f1_xf3_login_creates_verifiable_jwt(
    client: VIHttpClient, config: E2EConfig
) -> None:
    login_resp = client.login(config.username, config.password)
    assert login_resp.status_code == 200
    token = login_resp.json()["token"]

    verify_resp = client.verificar(token)
    assert verify_resp.status_code == 200
    v_data = verify_resp.json()
    assert v_data.get("valido") is True and v_data.get("usuario") == config.username


def test_t3_f1_xf1_concurrent_login_does_not_disrupt_f3_session(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, jwt1 = auth_session
    intruder = client.login(config.username, config.password)
    assert intruder.status_code == 401

    verify_resp = client.verificar(jwt1)
    assert verify_resp.status_code == 200
    assert verify_resp.json().get("valido") is True


def test_t3_f2_xf3_xf1_header_logout_invalidates_verify_and_unlocks_login(
    client: VIHttpClient, config: E2EConfig
) -> None:
    jwt1 = client.login(config.username, config.password).json()["token"]
    assert client.logout(jwt1).status_code == 200
    assert client.verificar(jwt1).status_code == 401

    relogin = client.login(config.username, config.password)
    assert relogin.status_code == 200
    jwt2 = relogin.json()["token"]
    assert client.verificar(jwt2).status_code == 200


def test_t3_f2_xf3_xf1_beacon_body_logout_invalidates_verify_and_unlocks_login(
    client: VIHttpClient, config: E2EConfig
) -> None:
    jwt1 = client.login(config.username, config.password).json()["token"]
    out = client.logout(jwt1, via_body=True)
    assert out.status_code == 200
    assert client.verificar(jwt1).status_code == 401

    relogin = client.login(config.username, config.password)
    assert relogin.status_code == 200
    assert client.verificar(relogin.json()["token"]).status_code == 200


def test_t3_f4_xf5_step1_then_step2_then_f1_new_password_and_restore(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    rotated = "NuevaClaveVI2026*"
    step2 = client.recuperar_actualizar(config.email, otp, rotated, rotated)
    assert step2.status_code == 200

    assert client.login(config.username, config.password).status_code == 401
    new_login = client.login(config.username, rotated)
    assert new_login.status_code == 200
    assert client.logout(new_login.json()["token"]).status_code == 200


def test_t3_f1_xf4_xf5_password_reset_evicts_active_f1_session(
    auth_session: tuple[VIHttpClient, str],
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    client, jwt1 = auth_session
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    rotated = "EvictSessionVI2026*"
    assert client.recuperar_actualizar(config.email, otp, rotated, rotated).status_code == 200

    # Active session jwt1 must be evicted immediately without calling /logout
    assert client.verificar(jwt1).status_code == 401
    # New login works right away because token_sesion_unica was cleared
    new_login = client.login(config.username, rotated)
    assert new_login.status_code == 200


def test_t3_f4_xf4_second_step1_invalidates_first_otp(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    b1 = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp1 = otp_extractor(config.email, baseline=b1)

    b2 = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp2 = otp_extractor(config.email, baseline=b2)

    if otp1 != otp2:
        stale = client.recuperar_actualizar(
            config.email, otp1, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
        )
        assert stale.status_code in (400, 401)

    valid = client.recuperar_actualizar(
        config.email, otp2, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
    )
    assert valid.status_code == 200


def test_t3_f6_xf1_xf3_attack_burst_preserves_active_session(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, jwt1 = auth_session
    assert client.post_json(
        "/api/auth/login", {"usuario": {"$ne": ""}, "clave": {"$gt": ""}}
    ).status_code == 422
    assert client.login("' OR 1=1 --", "<script>alert(1)</script>").status_code in (
        400,
        422,
    )
    assert client.verificar(jwt1[:-1] + ("A" if jwt1[-1] != "A" else "B")).status_code == 401
    assert client.recuperar_solicitar("'; DROP TABLE usuarios;--").status_code in (
        400,
        422,
    )

    assert client.verificar(jwt1).status_code == 200
    assert client.logout(jwt1).status_code == 200


def test_t3_f6_xf4_xf5_attack_payload_does_not_corrupt_pending_otp(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    assert (
        client.post_json(
            "/api/auth/recuperar",
            {
                "accion": "actualizar_clave",
                "correo": config.email,
                "codigo": {"$ne": ""},
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
            },
        ).status_code
        == 422
    )
    assert (
        client.recuperar_actualizar(
            config.email, otp, "<script>alert(1)</script>", "<script>alert(1)</script>"
        ).status_code
        in (400, 422)
    )

    assert (
        client.recuperar_actualizar(
            config.email, otp, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
        ).status_code
        == 200
    )


def test_t3_f8_xf1_xf4_seed_username_and_seed_email_correspond_to_same_account(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    rotated = "CuentaUnicaVI2026*"
    assert (
        client.recuperar_actualizar(config.email, otp, rotated, rotated).status_code
        == 200
    )
    assert client.login(config.username, config.password).status_code == 401
    ok = client.login(config.username, rotated)
    assert ok.status_code == 200
    assert ok.json().get("usuario") == config.username


# ---------------------------------------------------------------------------
# Pairwise Frontend F7 x Backend API Combinations — 5 tests
# ---------------------------------------------------------------------------


def test_t3_f7_f3_monitoreo_guard_and_verificar_contract(
    client: VIHttpClient, config: E2EConfig
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/monitoreo")
    mon_js = "\n".join(strip_js_comments(r.text) for r in bundle["js"].values())
    assert "/api/auth/verificar" in mon_js
    assert "Bearer" in mon_js
    assert "sessionStorage" in mon_js
    assert "/login" in mon_js

    assert client.verificar(None).status_code == 401
    tok = client.login(config.username, config.password).json()["token"]
    verify_ok = client.verificar(tok)
    assert verify_ok.status_code == 200
    v_data = verify_ok.json()
    assert v_data.get("valido") is True and v_data.get("usuario") == config.username
    assert client.logout(tok).status_code == 200
    assert client.verificar(tok).status_code == 401


def test_t3_f7_f2_unload_logout_json_body_contract(
    client: VIHttpClient, config: E2EConfig
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/monitoreo")
    mon_js = "\n".join(strip_js_comments(r.text) for r in bundle["js"].values())
    assert re.search(r"pagehide|beforeunload", mon_js)
    assert "/api/auth/logout" in mon_js
    assert re.search(r"keepalive|sendBeacon", mon_js)
    assert "token" in mon_js

    tok = client.login(config.username, config.password).json()["token"]
    beacon_logout = client.logout(tok, via_body=True)
    assert beacon_logout.status_code == 200
    assert client.verificar(tok).status_code == 401
    assert client.login(config.username, config.password).status_code == 200


def test_t3_f7_f1_login_ui_api_payload_and_fig9_error_alignment(
    client: VIHttpClient, config: E2EConfig
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/login")
    login_js = "\n".join(strip_js_comments(r.text) for r in bundle["js"].values())
    login_combined = bundle["page"].text + "\n" + login_js
    assert "/api/auth/login" in login_js
    assert "usuario" in login_js and "clave" in login_js
    assert "vi_jwt_token" in login_js
    assert (
        "Credenciales inválidas o sesión única ya activa." in login_combined
        or ("detail" in login_js and ".textContent" in login_js)
    )

    bad_login = client.login(config.username, "WrongPass2026*")
    assert bad_login.status_code == 401
    assert "Credenciales inválidas o sesión única ya activa." in bad_login.json().get(
        "detail", ""
    )

    good = client.login(config.username, config.password)
    assert good.status_code == 200
    concurrent = client.login(config.username, config.password)
    assert concurrent.status_code == 401
    assert "Credenciales inválidas o sesión única ya activa." in concurrent.json().get(
        "detail", ""
    )


def test_t3_f7_f4_f5_recuperar_two_step_ui_api_alignment(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/recuperar")
    rec_js = "\n".join(strip_js_comments(r.text) for r in bundle["js"].values())
    assert "/api/auth/recuperar" in rec_js
    assert "solicitar_codigo" in rec_js
    assert "actualizar_clave" in rec_js
    assert "nueva_clave" in rec_js and "confirmar_clave" in rec_js

    baseline = log_baseline(config.email)
    step1 = client.recuperar_solicitar(config.email)
    assert step1.status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    mismatch = client.recuperar_actualizar(
        config.email, otp, "NuevaClaveVI2026*", "DistintaVI2026*"
    )
    assert mismatch.status_code in (400, 401, 422)

    wrong_code = "000000" if otp != "000000" else "999999"
    assert (
        client.recuperar_actualizar(
            config.email, wrong_code, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
        ).status_code
        in (400, 401)
    )

    ok_step2 = client.recuperar_actualizar(
        config.email, otp, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
    )
    assert ok_step2.status_code == 200


def test_t3_f7_f6_csp_and_client_server_injection_parity(
    client: VIHttpClient, config: E2EConfig
) -> None:
    for route in ("/login", "/recuperar"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        csp = bundle["page"].headers.get("content-security-policy", "")
        assert "script-src 'self'" in csp
        assert "connect-src 'self'" in csp
        active_js = "\n".join(strip_js_comments(r.text) for r in bundle["js"].values())
        assert re.search(
            r"\\\$|\$(?:ne|gt|gte|lt|lte|where|regex|or|and)\b|\[[^\]]*\$",
            active_js,
            re.IGNORECASE,
        ) or (
            "$" in active_js
            and re.search(
                r"\b(?:test|includes|indexOf|match|search)\s*\(|\bRegExp\b", active_js
            )
        ), f"Expected client-side NoSQL operator validation pattern on {route}"
        assert re.search(
            r"<script|onerror|onload|javascript:|\[[^\]]*[<>]|\b(?:includes|indexOf|test|match|search)\s*\(\s*['\"][<>]",
            active_js,
            re.IGNORECASE,
        ), f"Expected client-side XSS validation pattern on {route}"

    for endpoint, payload in (
        ("/api/auth/login", {"usuario": {"$ne": ""}, "clave": {"$gt": ""}}),
        (
            "/api/auth/recuperar",
            {"accion": "solicitar_codigo", "correo": {"$ne": ""}},
        ),
    ):
        resp = client.post_json(endpoint, payload)
        assert resp.status_code == 422
        assert "traceback" not in resp.text.lower()

    xss_resp = client.login("<script>alert(1)</script>", "x")
    assert xss_resp.status_code in (400, 422)
    assert "<script>" not in xss_resp.text.lower()
