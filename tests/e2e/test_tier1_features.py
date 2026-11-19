"""Tier 1: Feature Coverage opaque-box E2E tests (>=5 tests per feature F1-F8)."""

from __future__ import annotations

import re
import time

from conftest import (
    DockerInspector,
    E2EConfig,
    VIHttpClient,
    decode_jwt_payload_unverified,
    discover_and_fetch_page_bundle,
    extract_css_custom_properties,
    resolve_css_vars,
    strip_css_comments,
    strip_js_comments,
)


# ---------------------------------------------------------------------------
# F1: Login (POST /api/auth/login) — 6 tests
# ---------------------------------------------------------------------------


def test_t1_f1_login_seed_user_returns_200_and_payload(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username, config.password)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data.get("usuario") == config.username
    assert isinstance(data.get("token"), str) and len(data["token"]) > 20
    assert isinstance(data.get("mensaje"), str) and data["mensaje"].strip()


def test_t1_f1_login_jwt_structure_opaque_decode(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    _client, token = auth_session
    header, payload = decode_jwt_payload_unverified(token)
    assert header.get("alg") == "HS256"
    assert header.get("typ", "JWT") == "JWT"
    assert (
        payload.get("sub") == config.username
        or payload.get("usuario") == config.username
    )
    assert isinstance(payload.get("exp"), (int, float))
    if "iat" in payload:
        assert isinstance(payload.get("iat"), (int, float))
        assert payload["exp"] > payload["iat"]
    else:
        assert payload["exp"] > time.time()


def test_t1_f1_login_wrong_password_returns_401(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username, "WrongPassword2026!")
    assert resp.status_code == 401
    data = resp.json()
    assert "detail" in data
    assert "Credenciales" in data["detail"] or "sesión" in data["detail"].lower()


def test_t1_f1_login_unknown_user_returns_401(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login("unknown_op", config.password)
    assert resp.status_code == 401
    data = resp.json()
    assert "detail" in data


def test_t1_f1_login_relogin_succeeds_after_logout(
    client: VIHttpClient, config: E2EConfig
) -> None:
    r1 = client.login(config.username, config.password)
    assert r1.status_code == 200
    token1 = r1.json()["token"]

    out = client.logout(token1)
    assert out.status_code == 200

    r2 = client.login(config.username, config.password)
    assert r2.status_code == 200
    token2 = r2.json()["token"]
    assert isinstance(token2, str) and len(token2) > 20
    v2 = client.verificar(token2)
    assert v2.status_code == 200
    assert v2.json().get("valido") is True


def test_t1_f1_login_concurrent_session_blocked_401(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, active_token = auth_session
    second = client.login(config.username, config.password)
    assert second.status_code == 401
    detail = second.json().get("detail", "")
    assert "Credenciales inválidas o sesión única ya activa" in detail or "sesión" in detail.lower()

    verify = client.verificar(active_token)
    assert verify.status_code == 200
    assert verify.json().get("valido") is True


# ---------------------------------------------------------------------------
# F2: Logout (POST /api/auth/logout) — 5 tests
# ---------------------------------------------------------------------------


def test_t1_f2_logout_with_bearer_header_returns_200(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    resp = client.logout(token)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data.get("mensaje"), str) and data["mensaje"].strip()


def test_t1_f2_logout_with_json_body_only_returns_200(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    resp = client.logout(token, via_body=True)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data.get("mensaje"), str) and data["mensaje"].strip()


def test_t1_f2_logout_with_both_header_and_body_returns_200(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    resp = client.logout(token, via_both=True)
    assert resp.status_code == 200
    assert "mensaje" in resp.json()


def test_t1_f2_logout_releases_session_lock(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, token = auth_session
    assert client.logout(token).status_code == 200
    relogin = client.login(config.username, config.password)
    assert relogin.status_code == 200
    assert relogin.json().get("token")


def test_t1_f2_logout_without_credentials_returns_401(client: VIHttpClient) -> None:
    resp = client.logout(None)
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# F3: Session Verification (GET /api/auth/verificar) — 5 tests
# ---------------------------------------------------------------------------


def test_t1_f3_verify_active_token_returns_200(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, token = auth_session
    resp = client.verificar(token)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("valido") is True
    assert data.get("usuario") == config.username


def test_t1_f3_verify_without_header_returns_401(client: VIHttpClient) -> None:
    resp = client.verificar(None)
    assert resp.status_code == 401


def test_t1_f3_verify_after_logout_returns_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    assert client.logout(token).status_code == 200
    resp = client.verificar(token)
    assert resp.status_code == 401


def test_t1_f3_verify_malformed_token_returns_401(client: VIHttpClient) -> None:
    for malformed in ("not.a.jwt", "abc"):
        resp = client.verificar(malformed)
        assert resp.status_code == 401


def test_t1_f3_verify_alias_or_active_session_consistency(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, token = auth_session
    for _ in range(3):
        resp = client.verificar(token)
        assert resp.status_code == 200
        v_data = resp.json()
        assert v_data.get("valido") is True and v_data.get("usuario") == config.username
    alias_resp = client.verificar(token, path="/api/auth/verify")
    assert alias_resp.status_code in (200, 404)
    if alias_resp.status_code == 200:
        assert alias_resp.json().get("valido") is True


# ---------------------------------------------------------------------------
# F4: Recovery Step 1 (POST /api/auth/recuperar, solicitar_codigo) — 5 tests
# ---------------------------------------------------------------------------


def test_t1_f4_recovery_step1_registered_email_returns_200(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.recuperar_solicitar(config.email)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("correo") == config.email
    assert isinstance(data.get("mensaje"), str) and data["mensaje"].strip()


def test_t1_f4_recovery_step1_logs_six_digit_otp(
    client: VIHttpClient, config: E2EConfig, log_baseline, otp_extractor
) -> None:
    baseline = log_baseline(config.email)
    resp = client.recuperar_solicitar(config.email)
    assert resp.status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)
    assert re.fullmatch(r"\d{6}", otp), f"Expected 6-digit OTP, got {otp!r}"


def test_t1_f4_recovery_step1_unregistered_email_rejected(
    client: VIHttpClient
) -> None:
    resp = client.recuperar_solicitar("otro@espe.edu.ec")
    assert resp.status_code in (400, 404)


def test_t1_f4_recovery_step1_invalid_email_format_rejected(
    client: VIHttpClient
) -> None:
    resp = client.recuperar_solicitar("not-an-email")
    assert resp.status_code in (400, 422)


def test_t1_f4_recovery_step1_resend_issues_new_200(
    client: VIHttpClient, config: E2EConfig, log_baseline, otp_extractor
) -> None:
    b1 = log_baseline(config.email)
    r1 = client.recuperar_solicitar(config.email)
    assert r1.status_code == 200
    otp1 = otp_extractor(config.email, baseline=b1)
    assert re.fullmatch(r"\d{6}", otp1)

    b2 = log_baseline(config.email)
    r2 = client.recuperar_solicitar(config.email)
    assert r2.status_code == 200
    otp2 = otp_extractor(config.email, baseline=b2)
    assert re.fullmatch(r"\d{6}", otp2)


# ---------------------------------------------------------------------------
# F5: Recovery Step 2 (POST /api/auth/recuperar, actualizar_clave) — 5 tests
# ---------------------------------------------------------------------------


def test_t1_f5_recovery_step2_valid_otp_updates_password(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    new_pw = "NuevaClaveVI2026*"
    resp = client.recuperar_actualizar(config.email, otp, new_pw, new_pw)
    assert resp.status_code == 200
    assert isinstance(resp.json().get("mensaje"), str)

    login_new = client.login(config.username, new_pw)
    assert login_new.status_code == 200


def test_t1_f5_recovery_step2_wrong_otp_rejected(
    client: VIHttpClient, config: E2EConfig, log_baseline, otp_extractor
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    real_otp = otp_extractor(config.email, baseline=baseline)
    wrong_otp = "000000" if real_otp != "000000" else "999999"

    resp = client.recuperar_actualizar(
        config.email, wrong_otp, "NuevaClaveVI2026*", "NuevaClaveVI2026*"
    )
    assert resp.status_code in (400, 401)

    still_ok = client.login(config.username, config.password)
    assert still_ok.status_code == 200


def test_t1_f5_recovery_step2_mismatched_passwords_rejected(
    client: VIHttpClient, config: E2EConfig, log_baseline, otp_extractor
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    resp = client.recuperar_actualizar(
        config.email, otp, "NuevaClaveVI2026*", "OtraClaveVI2026*"
    )
    assert resp.status_code in (400, 401, 422)


def test_t1_f5_recovery_step2_clears_otp_prevents_replay(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    new_pw = "NuevaClaveVI2026*"
    first = client.recuperar_actualizar(config.email, otp, new_pw, new_pw)
    assert first.status_code == 200

    replay = client.recuperar_actualizar(
        config.email, otp, "OtraClaveVI2026*", "OtraClaveVI2026*"
    )
    assert replay.status_code in (400, 401)


def test_t1_f5_recovery_step2_clears_active_session_token(
    auth_session: tuple[VIHttpClient, str],
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    client, active_jwt = auth_session
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)

    new_pw = "NuevaClaveVI2026*"
    assert client.recuperar_actualizar(config.email, otp, new_pw, new_pw).status_code == 200

    verify = client.verificar(active_jwt)
    assert verify.status_code == 401


# ---------------------------------------------------------------------------
# F6: Security Validation & Headers (R4) — 6 tests
# ---------------------------------------------------------------------------


def _assert_security_headers(headers: dict[str, str], context: str) -> None:
    assert headers.get("x-content-type-options", "").lower() == "nosniff", (
        f"Missing X-Content-Type-Options=nosniff on {context}: {headers}"
    )
    assert headers.get("x-frame-options", "").upper() == "DENY", (
        f"Missing X-Frame-Options=DENY on {context}: {headers}"
    )
    csp = headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp and "script-src 'self'" in csp, (
        f"Invalid Content-Security-Policy on {context}: {csp!r}"
    )


def test_t1_f6_security_headers_on_auth_api_responses(
    auth_session: tuple[VIHttpClient, str], config: E2EConfig
) -> None:
    client, token = auth_session
    login_resp = client.login(config.username, "WrongPassword!")
    _assert_security_headers(login_resp.headers, "POST /api/auth/login")

    verify_resp = client.verificar(token)
    _assert_security_headers(verify_resp.headers, "GET /api/auth/verificar")


def test_t1_f6_security_headers_on_html_views(client: VIHttpClient) -> None:
    for route in ("/login", "/recuperar", "/monitoreo"):
        resp = client.get(route)
        assert resp.status_code == 200
        _assert_security_headers(resp.headers, f"GET {route}")


def test_t1_f6_nosqli_dict_operator_rejected_login(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.post_json(
        "/api/auth/login",
        {"usuario": {"$ne": ""}, "clave": config.password},
    )
    assert resp.status_code == 422


def test_t1_f6_sqli_string_rejected_login(client: VIHttpClient) -> None:
    resp = client.login("' OR 1=1 --", "x")
    assert resp.status_code in (400, 422)


def test_t1_f6_xss_payload_rejected_no_reflection(client: VIHttpClient) -> None:
    payload = "<script>alert(1)</script>"
    resp = client.login(payload, "x")
    assert resp.status_code in (400, 422)
    assert "<script>" not in resp.text.lower()
    assert "traceback" not in resp.text.lower()


def test_t1_f6_extra_json_field_forbidden_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.post_json(
        "/api/auth/login",
        {"usuario": config.username, "clave": config.password, "role": "admin"},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# F7: Frontend Views, JS Security & DESIGN.md CSS (R3/R4) — 7 tests
# ---------------------------------------------------------------------------


def test_t1_f7_root_and_login_html_wireframe_fig8(
    client: VIHttpClient, config: E2EConfig
) -> None:
    for path in ("/", "/login"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, path)
        page = bundle["page"]
        insp = bundle["inspector"]
        assert "text/html" in page.headers.get("content-type", "").lower()

        text = insp.visible_text
        assert "V.I" in text
        assert "Sistema de Vigilancia Inteligente" in text
        assert any(
            "BIENVENIDO" in h_text.upper()
            for tag, h_text in insp.headings
            if tag in ("h1", "h2")
        )
        assert "Usuario" in text
        assert "Contraseña" in text
        assert "* Campos obligatorios. Al cerrar el navegador la sesión expira." in text

        text_inputs = [i for i in insp.inputs if i.get("type", "text").lower() == "text"]
        pw_inputs = [i for i in insp.inputs if i.get("type", "").lower() == "password"]
        assert any(
            i.get("placeholder") == "Ingrese su usuario"
            for i in text_inputs
        )
        assert any(
            i.get("placeholder") == "Ingrese su contraseña"
            for i in pw_inputs
        )

        toggle_btns = [
            b for b in insp.buttons
            if b.get("type", "").lower() == "button" and "Mostrar" in b.get("text", "")
        ]
        assert len(toggle_btns) >= 1
        assert any("INICIAR SESIÓN" in b.get("text", "").upper() for b in insp.buttons)

        has_recovery_link = any(
            "¿Olvidó su contraseña?" in a.get("text", "")
            and "/recuperar" in a.get("href", "")
            for a in insp.anchors
        ) or ("¿Olvidó su contraseña?" in text and "/recuperar" in page.text)
        assert has_recovery_link

        assert len(bundle["css"]) >= 1
        assert len(bundle["js"]) >= 1
        assert all(r.status_code == 200 for r in bundle["css"].values())
        assert all(r.status_code == 200 for r in bundle["js"].values())


def test_t1_f7_recuperar_html_wireframe_fig10_fig11(
    client: VIHttpClient, config: E2EConfig
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/recuperar")
    page = bundle["page"]
    insp = bundle["inspector"]
    assert "text/html" in page.headers.get("content-type", "").lower()

    text = insp.visible_text
    assert "V.I" in text
    assert "Sistema de Vigilancia Inteligente" in text
    assert any(
        "RECUPERAR CONTRASEÑA" in h_text.upper()
        for tag, h_text in insp.headings
        if tag in ("h1", "h2")
    )
    assert "1. Verificar correo" in text
    assert "2. Nueva contraseña" in text
    assert "Correo electrónico registrado" in text
    assert "Código temporal" in text
    assert "Nueva contraseña" in text
    assert "Confirmar nueva contraseña" in text
    assert "* Campos obligatorios. Recibirá un código temporal de 6 dígitos." in text

    assert any(
        i.get("type", "").lower() == "email"
        and i.get("placeholder") == "Ingrese su correo electrónico"
        for i in insp.inputs
    )
    assert any(
        i.get("placeholder") == "Ingrese el código de 6 dígitos"
        and i.get("maxlength") == "6"
        for i in insp.inputs
    )
    assert any(
        i.get("type", "").lower() == "password"
        and i.get("placeholder") == "Ingrese la nueva contraseña"
        for i in insp.inputs
    )
    assert any(
        i.get("type", "").lower() == "password"
        and i.get("placeholder") == "Repita la nueva contraseña"
        for i in insp.inputs
    )

    mostrar_btns = [
        b for b in insp.buttons
        if b.get("type", "").lower() == "button" and "Mostrar" in b.get("text", "")
    ]
    assert len(mostrar_btns) >= 2
    assert any(
        "ENVIAR CÓDIGO DE VERIFICACIÓN" in b.get("text", "").upper()
        for b in insp.buttons
    )
    assert any(
        "ACTUALIZAR CONTRASEÑA" in b.get("text", "").upper()
        for b in insp.buttons
    )
    assert any("Reenviar código" in b.get("text", "") for b in insp.buttons) or (
        "Reenviar código" in text
    )
    has_back_to_login = any(
        "Volver al Inicio de Sesión" in a.get("text", "")
        and (a.get("href", "") == "/" or "/login" in a.get("href", ""))
        for a in insp.anchors
    ) or any(
        "Volver al Inicio de Sesión" in b.get("text", "")
        for b in insp.buttons
    )
    assert has_back_to_login


def test_t1_f7_monitoreo_html_wireframe_fig12(
    client: VIHttpClient, config: E2EConfig
) -> None:
    bundle = discover_and_fetch_page_bundle(client, config.base_url, "/monitoreo")
    insp = bundle["inspector"]
    assert "text/html" in bundle["page"].headers.get("content-type", "").lower()

    text = insp.visible_text
    assert "V.I" in text
    assert "Sistema de Vigilancia Inteligente" in text
    assert any("Cerrar Sesión" in b.get("text", "") for b in insp.buttons)

    for expected_snippet in (
        "Monitoreo en Vivo",
        "Modo Evaluación",
        "Historial y Reportes",
        "CÁMARA EN TIEMPO REAL",
        "Cámara desconectada",
        "Cámara en espera",
        "Presione Iniciar Cámara para conectar la transmisión en vivo.",
        "Velocidad",
        "-- FPS",
        "Inferencia",
        "-- ms",
        "Área Cerco",
        "-- %",
        "CPU",
        "RAM",
        "-- MB",
        "Peatones / Alertas",
        "0 / 0",
        "AJUSTE DE UMBRALES",
        "Tiempo de permanencia",
        "15 s",
        "5 s",
        "60 s",
        "Trayectoria recurrente",
        "Baja",
        "Media",
        "Alta",
        "ALERTAS EN TIEMPO REAL",
        "Sin alertas registradas",
        "en la sesión actual.",
    ):
        assert expected_snippet in text, f"Missing Fig 12 copy {expected_snippet!r}"

    btn_by_text = {b.get("text", ""): b for b in insp.buttons}
    assert any("Iniciar Cámara" in k and "disabled" not in v for k, v in btn_by_text.items())
    assert any("Dibujar Cerco" in k and "disabled" in v for k, v in btn_by_text.items())
    assert any("Limpiar Cerco" in k and "disabled" in v for k, v in btn_by_text.items())
    assert any("APLICAR UMBRALES" in k.upper() and "disabled" in v for k, v in btn_by_text.items())

    ranges = [i for i in insp.inputs if i.get("type", "").lower() == "range"]
    assert len(ranges) >= 2, f"Expected 2 range sliders on /monitoreo, got {ranges}"
    assert any(
        r.get("min") == "5" and r.get("max") == "60" and r.get("value") == "15"
        for r in ranges
    )


def test_t1_f7_served_css_design_md_palette_and_tokens(
    client: VIHttpClient, config: E2EConfig
) -> None:
    css_blobs: list[str] = []
    for route in ("/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        assert bundle["css"], f"No stylesheet discovered on {route}"
        for url, resp in bundle["css"].items():
            assert resp.status_code == 200, f"CSS {url} returned {resp.status_code}"
            assert "text/css" in resp.headers.get("content-type", "").lower()
            css_blobs.append(strip_css_comments(resp.text))

    combined_css = "\n".join(css_blobs).lower()
    for hex_token in (
        "#f7f7f4",
        "#fafaf7",
        "#ffffff",
        "#26251e",
        "#f54e00",
        "#1f8a65",
        "#cf2d56",
        "#e6e5e0",
        "#cfcdc4",
    ):
        assert hex_token in combined_css, f"Missing DESIGN.md token {hex_token} in CSS"

    css_props = extract_css_custom_properties(combined_css)
    resolved_radii = [
        resolve_css_vars(val, css_props)
        for val in re.findall(r"border-radius\s*:\s*([^;}{]+)", combined_css)
    ]
    resolved_weights = [
        resolve_css_vars(val, css_props)
        for val in re.findall(r"font-weight\s*:\s*([^;}{]+)", combined_css)
    ]

    assert re.search(r"1px\s+solid", combined_css), "Expected 1px solid hairline border"
    assert (
        any(re.search(r"\b8px\b", r) for r in resolved_radii)
        or "--radius-md" in combined_css
        or "--rounded-md" in combined_css
    )
    assert (
        any(re.search(r"\b12px\b", r) for r in resolved_radii)
        or "--radius-lg" in combined_css
        or "--rounded-lg" in combined_css
    )
    assert any(re.search(r"\b400\b", w) for w in resolved_weights)
    assert "jetbrains mono" in combined_css or "monospace" in combined_css


def test_t1_f7_served_js_session_storage_and_safe_dom(
    client: VIHttpClient, config: E2EConfig
) -> None:
    js_blobs: list[str] = []
    for route in ("/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        assert bundle["js"], f"No external JS discovered on {route}"
        for url, resp in bundle["js"].items():
            assert resp.status_code == 200, f"JS {url} returned {resp.status_code}"
            ctype = resp.headers.get("content-type", "").lower()
            assert "javascript" in ctype, f"Unexpected JS Content-Type {ctype!r} on {url}"
            js_blobs.append(strip_js_comments(resp.text))

    combined_js = "\n".join(js_blobs)
    assert "sessionStorage" in combined_js
    assert "vi_jwt_token" in combined_js
    assert ".textContent" in combined_js
    assert "Ocultar" in combined_js and "Mostrar" in combined_js
    assert re.search(r"""['"]password['"]""", combined_js) and re.search(
        r"""['"]text['"]""", combined_js
    )


def test_t1_f7_served_js_login_and_recuperar_dynamic_copy(
    client: VIHttpClient, config: E2EConfig
) -> None:
    login_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/login")
    login_js = "\n".join(strip_js_comments(r.text) for r in login_bundle["js"].values())
    login_combined = login_bundle["page"].text + "\n" + login_js
    assert "/api/auth/login" in login_js
    assert (
        "Credenciales inválidas o sesión única ya activa." in login_combined
        or ("detail" in login_js and ".textContent" in login_js)
    )
    assert (
        "Verifique su usuario y contraseña e intente nuevamente." in login_combined
        or ".textContent" in login_js
    )

    rec_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/recuperar")
    rec_js = "\n".join(strip_js_comments(r.text) for r in rec_bundle["js"].values())
    rec_combined = rec_bundle["page"].text + "\n" + rec_js
    assert "/api/auth/recuperar" in rec_js
    assert "solicitar_codigo" in rec_js
    assert "actualizar_clave" in rec_js
    assert "Código enviado al correo" in rec_combined or (
        "mensaje" in rec_js and ".textContent" in rec_js
    )
    assert (
        "Ingrese el código temporal y defina su nueva contraseña." in rec_combined
        or "2. Nueva contraseña" in rec_combined
    )
    assert "Ambas contraseñas deben coincidir" in rec_combined or (
        "coincidir" in rec_combined.lower()
    )


def test_t1_f7_served_js_monitoreo_guard_and_logout_hooks(
    client: VIHttpClient, config: E2EConfig
) -> None:
    mon_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/monitoreo")
    mon_js = "\n".join(strip_js_comments(r.text) for r in mon_bundle["js"].values())
    assert "sessionStorage" in mon_js
    assert "/api/auth/verificar" in mon_js
    assert "Bearer" in mon_js
    assert "/login" in mon_js
    assert "/api/auth/logout" in mon_js
    assert "pagehide" in mon_js or "beforeunload" in mon_js
    assert "keepalive" in mon_js or "sendBeacon" in mon_js


# ---------------------------------------------------------------------------
# F8: Infrastructure, Local MongoDB & Seed Readiness (R1, RNF-08) — 5 tests
# ---------------------------------------------------------------------------


def test_t1_f8_seed_user_login_ready_on_startup(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username, config.password)
    assert resp.status_code == 200
    assert resp.json().get("usuario") == config.username


def test_t1_f8_seed_email_recovery_ready_on_startup(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.recuperar_solicitar(config.email)
    assert resp.status_code == 200
    assert resp.json().get("correo") == config.email


def test_t1_f8_served_pages_and_css_return_200(client: VIHttpClient) -> None:
    for route in ("/", "/login", "/recuperar", "/monitoreo", "/static/css/styles.css"):
        resp = client.get(route)
        assert resp.status_code == 200, f"GET {route} failed with {resp.status_code}"


def test_t1_f8_zero_atlas_mentions_in_served_assets(
    client: VIHttpClient, config: E2EConfig
) -> None:
    for route in ("/", "/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        payloads = [bundle["page"].text]
        payloads.extend(r.text for r in bundle["css"].values())
        payloads.extend(r.text for r in bundle["js"].values())
        for text in payloads:
            assert "MongoDB Atlas" not in text
            assert "RepositorioMongoDBAtlas" not in text
            assert "mongodb+srv://" not in text


def test_t1_f8_docker_compose_and_bcrypt_12_seed_hash(
    client: VIHttpClient,
    config: E2EConfig,
    docker_inspector: DockerInspector,
) -> None:
    compose_text = docker_inspector.read_compose_file()
    if compose_text is not None:
        assert "mongodb+srv://" not in compose_text
        assert "MongoDB Atlas" not in compose_text
        assert "mongo:" in compose_text
        assert not re.search(r"""["']?27017:27017["']?""", compose_text)

    ps_items = docker_inspector.get_compose_ps()
    if ps_items:
        services = {
            (item.get("Service") or item.get("Name") or "").lower(): item
            for item in ps_items
        }
        assert any("mongo" in k for k in services), f"No mongodb service in ps: {services}"
        assert any("vi-app" in k or "app" in k for k in services), f"No vi-app in ps: {services}"
        for svc_name, info in services.items():
            state = str(info.get("State", "")).lower()
            if state:
                assert "running" in state or "up" in state, f"{svc_name} not running: {info}"

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
        assert len(seed_docs) == 1, f"Expected 1 seed user {config.username!r}, got {docs}"
        seed = seed_docs[0]
        assert seed.get("correo") == config.email
        assert "password" not in seed
        pw_hash = seed.get("password_hash", "")
        assert re.match(r"^\$2[aby]\$12\$", pw_hash), (
            f"Expected Bcrypt 12-round hash, got {pw_hash!r}"
        )
    else:
        # Opaque-box fallback when VI_DOCKER_CHECKS=0 or running remotely without Docker
        r = client.login(config.username, config.password)
        assert r.status_code == 200
