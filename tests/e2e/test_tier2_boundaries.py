"""Tier 2: Boundary, Corner-Case, and R4 Security E2E tests (>=5 per feature F1-F8)."""

from __future__ import annotations

import re
import time
from typing import Any
import urllib.parse

import pytest

from conftest import (
    DockerInspector,
    E2EConfig,
    VIHttpClient,
    b64url_encode,
    decode_jwt_payload_unverified,
    discover_and_fetch_page_bundle,
    extract_css_custom_properties,
    resolve_css_vars,
    strip_css_comments,
    strip_js_comments,
)


# ---------------------------------------------------------------------------
# F1: Login Boundaries — 7 tests
# ---------------------------------------------------------------------------


def test_t2_f1_empty_usuario_and_clave_rejected(client: VIHttpClient) -> None:
    resp = client.login("", "")
    assert resp.status_code in (400, 422)


def test_t2_f1_whitespace_only_usuario_rejected(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login("   ", config.password)
    assert resp.status_code in (400, 401, 422)


def test_t2_f1_missing_required_keys_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    assert client.post_json("/api/auth/login", {}).status_code == 422
    assert (
        client.post_json("/api/auth/login", {"usuario": config.username}).status_code
        == 422
    )


def test_t2_f1_non_string_types_rejected_422(client: VIHttpClient) -> None:
    for payload in (
        {"usuario": 123, "clave": True},
        {"usuario": ["vi"], "clave": "x"},
        {"usuario": None, "clave": "x"},
    ):
        resp = client.post_json("/api/auth/login", payload)
        assert resp.status_code == 422


def test_t2_f1_password_72_byte_boundary_no_500(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username, "A" * 72)
    assert resp.status_code == 401, f"72B password must not 500; got {resp.status_code}"


def test_t2_f1_password_73_byte_ascii_rejected(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username, "A" * 73)
    assert resp.status_code in (400, 422)


def test_t2_f1_password_74_byte_multibyte_utf8_rejected(
    client: VIHttpClient, config: E2EConfig
) -> None:
    clave_74b = "ñ" * 37  # 37 chars = 74 UTF-8 bytes (> 72-byte Bcrypt limit)
    assert len(clave_74b.encode("utf-8")) == 74
    resp = client.login(config.username, clave_74b)
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# F2: Logout Boundaries — 5 tests
# ---------------------------------------------------------------------------


def test_t2_f2_logout_double_invocation_second_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    first = client.logout(token)
    assert first.status_code == 200
    second = client.logout(token)
    assert second.status_code == 401


def test_t2_f2_logout_tampered_jwt_signature_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    parts = token.split(".")
    flipped = ("A" if parts[2][-1] != "A" else "B")
    tampered = f"{parts[0]}.{parts[1]}.{parts[2][:-1]}{flipped}"

    resp = client.logout(tampered)
    assert resp.status_code == 401
    assert client.verificar(token).status_code == 200


def test_t2_f2_logout_empty_bearer_header_401(client: VIHttpClient) -> None:
    resp = client.request(
        "POST",
        "/api/auth/logout",
        raw_body=b"",
        headers={"Authorization": "Bearer "},
    )
    assert resp.status_code == 401


def test_t2_f2_logout_extra_body_key_422(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    resp = client.post_json("/api/auth/logout", {"token": token, "extra": "x"})
    assert resp.status_code == 422
    assert client.verificar(token).status_code == 200


def test_t2_f2_logout_non_string_token_422(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    resp = client.post_json("/api/auth/logout", {"token": {"$ne": ""}})
    assert resp.status_code == 422
    assert client.verificar(token).status_code == 200


# ---------------------------------------------------------------------------
# F3: Verify Boundaries — 6 tests
# ---------------------------------------------------------------------------


def test_t2_f3_verify_tampered_signature_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    parts = token.split(".")
    flipped = ("A" if parts[2][-1] != "A" else "B")
    tampered = f"{parts[0]}.{parts[1]}.{parts[2][:-1]}{flipped}"
    assert client.verificar(tampered).status_code == 401


def test_t2_f3_verify_tampered_payload_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    parts = token.split(".")
    _, payload = decode_jwt_payload_unverified(token)
    payload["sub"] = "admin"
    payload["exp"] = int(payload.get("exp", 0)) + 999999
    import json as _json

    forged_payload = b64url_encode(_json.dumps(payload).encode("utf-8"))
    forged = f"{parts[0]}.{forged_payload}.{parts[2]}"
    assert client.verificar(forged).status_code == 401


def test_t2_f3_verify_alg_none_downgrade_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    parts = token.split(".")
    none_header = b64url_encode(b'{"alg":"none","typ":"JWT"}')
    downgraded = f"{none_header}.{parts[1]}."
    assert client.verificar(downgraded).status_code == 401


def test_t2_f3_verify_wrong_auth_scheme_401(
    auth_session: tuple[VIHttpClient, str]
) -> None:
    client, token = auth_session
    assert client.verificar(token, scheme="Basic").status_code == 401
    assert client.verificar(token, scheme="").status_code == 401


def test_t2_f3_verify_empty_bearer_401(client: VIHttpClient) -> None:
    resp = client.get("/api/auth/verificar", headers={"Authorization": "Bearer    "})
    assert resp.status_code == 401


def test_t2_f3_verify_stale_jwt_after_logout_and_relogin_401(
    client: VIHttpClient, config: E2EConfig
) -> None:
    r1 = client.login(config.username, config.password)
    assert r1.status_code == 200
    jwt1 = r1.json()["token"]
    assert client.logout(jwt1).status_code == 200

    time.sleep(1.05)
    r2 = client.login(config.username, config.password)
    assert r2.status_code == 200
    jwt2 = r2.json()["token"]

    assert client.verificar(jwt1).status_code == 401
    assert client.verificar(jwt2).status_code == 200


# ---------------------------------------------------------------------------
# F4: Recovery Step 1 Boundaries — 5 tests
# ---------------------------------------------------------------------------


def test_t2_f4_step1_empty_correo_rejected(client: VIHttpClient) -> None:
    resp = client.recuperar_solicitar("")
    assert resp.status_code in (400, 422)


def test_t2_f4_step1_invalid_accion_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.post_json(
        "/api/auth/recuperar",
        {"accion": "reset_admin", "correo": config.email},
    )
    assert resp.status_code == 422


def test_t2_f4_step1_extra_body_key_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.post_json(
        "/api/auth/recuperar",
        {"accion": "solicitar_codigo", "correo": config.email, "admin": True},
    )
    assert resp.status_code == 422


def test_t2_f4_step1_non_scalar_correo_422(client: VIHttpClient) -> None:
    resp = client.post_json(
        "/api/auth/recuperar",
        {"accion": "solicitar_codigo", "correo": {"$ne": None}},
    )
    assert resp.status_code == 422


def test_t2_f4_step1_overlong_correo_rejected(client: VIHttpClient) -> None:
    overlong = ("a" * 250) + "@espe.edu.ec"
    resp = client.recuperar_solicitar(overlong)
    assert resp.status_code in (400, 404, 422)


# ---------------------------------------------------------------------------
# F5: Recovery Step 2 Boundaries — 6 tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_codigo", ["12345", "1234567", "12345a", 123456])
def test_t2_f5_step2_short_and_alpha_codigo_rejected(
    client: VIHttpClient, config: E2EConfig, bad_codigo
) -> None:
    resp = client.post_json(
        "/api/auth/recuperar",
        {
            "accion": "actualizar_clave",
            "correo": config.email,
            "codigo": bad_codigo,
            "nueva_clave": "NuevaClaveVI2026*",
            "confirmar_clave": "NuevaClaveVI2026*",
        },
    )
    assert resp.status_code in (400, 422)


def test_t2_f5_step2_without_prior_step1_rejected(
    client: VIHttpClient,
    config: E2EConfig,
    log_baseline,
    otp_extractor,
    password_restorer,
) -> None:
    # Clear any pending OTP from prior tests cleanly before probing empty OTP state
    baseline = log_baseline(config.email)
    assert client.recuperar_solicitar(config.email).status_code == 200
    otp = otp_extractor(config.email, baseline=baseline)
    assert (
        client.recuperar_actualizar(
            config.email, otp, config.password, config.password
        ).status_code
        == 200
    )

    resp = client.recuperar_actualizar(
        config.email, "123456", "NuevaClaveVI2026*", "NuevaClaveVI2026*"
    )
    assert resp.status_code in (400, 401)


def test_t2_f5_step2_short_password_under_8_chars_rejected(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.recuperar_actualizar(
        config.email, "123456", "Abc123*", "Abc123*"
    )
    assert resp.status_code in (400, 401, 422)


@pytest.mark.parametrize("bad_pw", ["A" * 73, "ñ" * 37])
def test_t2_f5_step2_over_72_byte_password_rejected(
    client: VIHttpClient, config: E2EConfig, bad_pw: str
) -> None:
    resp = client.recuperar_actualizar(config.email, "123456", bad_pw, bad_pw)
    assert resp.status_code in (400, 422)


def test_t2_f5_step2_extra_key_rejected_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.post_json(
        "/api/auth/recuperar",
        {
            "accion": "actualizar_clave",
            "correo": config.email,
            "codigo": "123456",
            "nueva_clave": "NuevaClaveVI2026*",
            "confirmar_clave": "NuevaClaveVI2026*",
            "role": "admin",
        },
    )
    assert resp.status_code == 422


def test_t2_f5_step2_unregistered_email_rejected(client: VIHttpClient) -> None:
    resp = client.recuperar_actualizar(
        "noexiste@espe.edu.ec",
        "123456",
        "NuevaClaveVI2026*",
        "NuevaClaveVI2026*",
    )
    assert resp.status_code in (400, 401, 404)


# ---------------------------------------------------------------------------
# F6: R4 Security Attack Vectors — 9 tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "nosql_dict",
    [
        {"$ne": ""},
        {"$gt": ""},
        {"$gte": ""},
        {"$where": "sleep(1000)"},
        {"$regex": ".*"},
        {"$or": [{"usuario": "vi"}]},
    ],
)
def test_t2_f6_nosqli_all_dict_operators_login(
    client: VIHttpClient, config: E2EConfig, nosql_dict: dict
) -> None:
    r_user = client.post_json(
        "/api/auth/login", {"usuario": nosql_dict, "clave": config.password}
    )
    assert r_user.status_code == 422

    r_pass = client.post_json(
        "/api/auth/login", {"usuario": config.username, "clave": nosql_dict}
    )
    assert r_pass.status_code == 422


@pytest.mark.parametrize(
    "nosql_str",
    [
        '{"$ne": ""}',
        "$gt",
        "$gte",
        "$where: function(){return true}",
        "$regex",
        "$or",
        'dsceli@espe.edu.ec" || "$ne"',
    ],
)
def test_t2_f6_nosqli_embedded_strings_login_and_recuperar(
    client: VIHttpClient, nosql_str: str
) -> None:
    r_login = client.login(nosql_str, "OperadorVI2026*")
    assert r_login.status_code in (400, 422)

    r_rec = client.recuperar_solicitar(nosql_str)
    assert r_rec.status_code in (400, 422)


@pytest.mark.parametrize(
    "nosql_dict",
    [{"$ne": ""}, {"$gt": ""}, {"$where": "1==1"}, {"$regex": ".*"}],
)
def test_t2_f6_nosqli_dict_operators_recuperar(
    client: VIHttpClient, config: E2EConfig, nosql_dict: dict
) -> None:
    r_step1 = client.post_json(
        "/api/auth/recuperar",
        {"accion": "solicitar_codigo", "correo": nosql_dict},
    )
    assert r_step1.status_code == 422

    r_step2_code = client.post_json(
        "/api/auth/recuperar",
        {
            "accion": "actualizar_clave",
            "correo": config.email,
            "codigo": nosql_dict,
            "nueva_clave": "NuevaClaveVI2026*",
            "confirmar_clave": "NuevaClaveVI2026*",
        },
    )
    assert r_step2_code.status_code == 422

    r_step2_pw = client.post_json(
        "/api/auth/recuperar",
        {
            "accion": "actualizar_clave",
            "correo": config.email,
            "codigo": "123456",
            "nueva_clave": nosql_dict,
            "confirmar_clave": nosql_dict,
        },
    )
    assert r_step2_pw.status_code == 422


@pytest.mark.parametrize(
    "sqli",
    [
        "' OR 1=1 --",
        "vi' UNION SELECT 1,2,3 --",
        "'; DROP TABLE usuarios;--",
    ],
)
def test_t2_f6_sqli_vectors_login_and_recuperar(
    client: VIHttpClient, config: E2EConfig, sqli: str
) -> None:
    r_login = client.login(sqli, "x")
    assert r_login.status_code in (400, 422)

    r_step1 = client.recuperar_solicitar(sqli)
    assert r_step1.status_code in (400, 422)

    r_step2 = client.recuperar_actualizar(config.email, "123456", sqli, sqli)
    assert r_step2.status_code in (400, 422)


@pytest.mark.parametrize(
    "xss",
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ],
)
def test_t2_f6_xss_vectors_login_and_recuperar(
    client: VIHttpClient, config: E2EConfig, xss: str
) -> None:
    r_login = client.login(xss, "x")
    assert r_login.status_code in (400, 422)
    assert "<script>" not in r_login.text.lower()
    assert "onerror=" not in r_login.text.lower()

    r_step1 = client.recuperar_solicitar(xss)
    assert r_step1.status_code in (400, 422)
    assert "<script>" not in r_step1.text.lower()

    r_step2 = client.recuperar_actualizar(config.email, "123456", xss, xss)
    assert r_step2.status_code in (400, 422)
    assert "<script>" not in r_step2.text.lower()


def test_t2_f6_null_bytes_rejected(
    client: VIHttpClient, config: E2EConfig
) -> None:
    assert client.login("vi\x00", config.password).status_code in (400, 422)
    assert client.login(config.username, "OperadorVI2026*\x00").status_code in (400, 422)
    assert client.recuperar_solicitar("dsceli@espe.edu.ec\x00").status_code in (400, 422)
    assert (
        client.recuperar_actualizar(
            config.email, "12345\x00", "NuevaClaveVI2026*", "NuevaClaveVI2026*"
        ).status_code
        in (400, 422)
    )


def test_t2_f6_extra_keys_all_post_endpoints_422(
    client: VIHttpClient, config: E2EConfig
) -> None:
    assert (
        client.post_json(
            "/api/auth/login",
            {"usuario": config.username, "clave": config.password, "debug": 1},
        ).status_code
        == 422
    )
    assert (
        client.post_json(
            "/api/auth/logout",
            {"token": "dummy.jwt.token", "force": True},
        ).status_code
        == 422
    )
    assert (
        client.post_json(
            "/api/auth/recuperar",
            {"accion": "solicitar_codigo", "correo": config.email, "extra": "x"},
        ).status_code
        == 422
    )
    assert (
        client.post_json(
            "/api/auth/recuperar",
            {
                "accion": "actualizar_clave",
                "correo": config.email,
                "codigo": "123456",
                "nueva_clave": "NuevaClaveVI2026*",
                "confirmar_clave": "NuevaClaveVI2026*",
                "role": "admin",
            },
        ).status_code
        == 422
    )


def test_t2_f6_malformed_json_and_wrong_method(client: VIHttpClient) -> None:
    bad_json = client.post_raw("/api/auth/login", b"{bad")
    assert bad_json.status_code in (400, 422)
    wrong_method = client.get("/api/auth/login")
    assert wrong_method.status_code == 405


def test_t2_f6_no_stack_trace_leak_on_errors(
    client: VIHttpClient, config: E2EConfig
) -> None:
    responses = [
        client.login(config.username, "bad"),
        client.post_raw("/api/auth/login", b"not json"),
        client.post_json("/api/auth/login", {"usuario": {"$ne": ""}, "clave": "x"}),
        client.verificar("invalid.jwt.value"),
        client.recuperar_solicitar("noexiste@espe.edu.ec"),
    ]
    for resp in responses:
        assert resp.status_code < 500
        lowered = resp.text.lower()
        assert "traceback" not in lowered
        assert 'file "/app' not in lowered
        assert "pymongo" not in lowered


# ---------------------------------------------------------------------------
# F7: Frontend Views, CSS & JS Security Boundaries (R3/R4) — 7 tests
# ---------------------------------------------------------------------------


def test_t2_f7_zero_external_cdns_and_strict_csp_html(
    client: VIHttpClient, config: E2EConfig
) -> None:
    forbidden_hosts = (
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "unpkg.com",
        "cdnjs",
        "jsdelivr",
        "cdn.",
    )
    for route in ("/", "/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        insp = bundle["inspector"]
        assert not bundle["external_urls"], (
            f"External CDN assets found on {route}: {bundle['external_urls']}"
        )
        for link in insp.all_links:
            href = link.get("href", "")
            if href.startswith(("http://", "https://", "//")):
                resolved = urllib.parse.urljoin(bundle["page_url"], href)
                assert urllib.parse.urlparse(resolved).netloc == urllib.parse.urlparse(
                    config.base_url
                ).netloc
        assert not insp.inline_scripts, (
            f"Inline <script> violates script-src 'self' on {route}"
        )
        assert not insp.inline_styles, (
            f"Inline <style> violates style-src 'self' on {route}"
        )
        assert not insp.inline_event_attrs, (
            f"Inline event handlers violate CSP on {route}: {insp.inline_event_attrs}"
        )
        for url, css_resp in bundle["css"].items():
            clean_css = strip_css_comments(css_resp.text).lower()
            for host in forbidden_hosts:
                assert host not in clean_css, f"External host {host} in {url}"


def test_t2_f7_css_zero_active_box_shadow(
    client: VIHttpClient, config: E2EConfig
) -> None:
    seen_css: set[str] = set()
    css_blobs: list[tuple[str, str]] = []
    for route in ("/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        for url, css_resp in bundle["css"].items():
            if url not in seen_css:
                seen_css.add(url)
                css_blobs.append((url, strip_css_comments(css_resp.text)))
    css_props = extract_css_custom_properties("\n".join(txt for _, txt in css_blobs))
    for url, clean_css in css_blobs:
        for match in re.finditer(r"box-shadow\s*:\s*([^;}{]+)", clean_css, re.I):
            raw_val = match.group(1).replace("!important", "").strip().lower()
            val = resolve_css_vars(raw_val, css_props)
            assert val in ("none", "0", "0px"), (
                f"DESIGN.md forbids drop shadows; found `box-shadow: {val}` in {url}"
            )


def test_t2_f7_css_display_weight_400_and_no_timeline_pastels(
    client: VIHttpClient, config: E2EConfig
) -> None:
    css_blobs: list[str] = []
    seen_css: set[str] = set()
    for route in ("/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        for url, css_resp in bundle["css"].items():
            if url not in seen_css:
                seen_css.add(url)
                css_blobs.append(strip_css_comments(css_resp.text))
    combined = "\n".join(css_blobs).lower()
    css_props = extract_css_custom_properties(combined)

    for pastel in ("#dfa88f", "#9fc9a2", "#9fbbe0", "#c0a8dd", "#c08532"):
        assert pastel not in combined, (
            f"AI timeline pastel {pastel} must not appear in auth/monitoring CSS"
        )

    heading_blocks = re.findall(
        r"(?:^|[}\s,])(?:h[1-3]|\.(?:display|title|card-title|auth-title|page-title)[a-z0-9_-]*)[^{]*\{([^}]*)\}",
        combined,
        flags=re.MULTILINE,
    )
    assert heading_blocks, "Expected display heading / h1-h3 CSS rule"
    resolved_heading_weights = [
        resolve_css_vars(m.group(1), css_props)
        for blk in heading_blocks
        for m in re.finditer(r"font-weight\s*:\s*([^;}{]+)", blk)
    ]
    assert any(re.search(r"\b400\b", w) for w in resolved_heading_weights), (
        "Display headings must keep font-weight: 400 per DESIGN.md"
    )
    for w in resolved_heading_weights:
        assert not re.search(r"\b(?:700|800|900|bold)\b", w), (
            f"Display heading rule must not use bold weight: {w!r}"
        )

    body_blocks = re.findall(r"(?:^|[}\s,])body\s*\{([^}]*)\}", combined, re.MULTILINE)
    assert body_blocks, "Expected body CSS rule"
    body_css = resolve_css_vars(" ".join(body_blocks), css_props)
    assert "#f7f7f4" in body_css
    assert not re.search(
        r"background(?:-color)?\s*:\s*(?:#000000|#000\b|#111111|#111\b|#ffffff|#fff\b)",
        body_css,
    )


def test_t2_f7_js_zero_localstorage_and_zero_unsafe_dom_sinks(
    client: VIHttpClient, config: E2EConfig
) -> None:
    forbidden_patterns = (
        (r"\blocalStorage\b", "localStorage"),
        (r"\.innerHTML\b", ".innerHTML"),
        (r"\.outerHTML\b", ".outerHTML"),
        (r"\.insertAdjacentHTML\b", ".insertAdjacentHTML"),
        (r"\bdocument\.write(?:ln)?\s*\(", "document.write"),
        (r"\beval\s*\(", "eval("),
        (r"\bnew\s+Function\s*\(", "new Function("),
        (r"\bdocument\.cookie\s*=", "document.cookie ="),
    )
    seen_js: set[str] = set()
    for route in ("/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        for url, js_resp in bundle["js"].items():
            if url in seen_js:
                continue
            seen_js.add(url)
            active_js = strip_js_comments(js_resp.text)
            for pattern, label in forbidden_patterns:
                assert not re.search(pattern, active_js), (
                    f"Forbidden JS sink/storage `{label}` found in {url}"
                )
            assert not re.search(
                r"""(?:(?:href|src|action|location(?:\.href)?)\s*=\s*|setAttribute\s*\(\s*['"](?:href|src|action)['"]\s*,\s*)['"`]\s*javascript:""",
                active_js,
                re.IGNORECASE,
            ), f"Forbidden `javascript:` sink assignment found in {url}"


def test_t2_f7_js_client_anti_nosqli_and_xss_validation(
    client: VIHttpClient, config: E2EConfig
) -> None:
    auth_js_parts: list[str] = []
    for route in ("/login", "/recuperar"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        for js_resp in bundle["js"].values():
            auth_js_parts.append(strip_js_comments(js_resp.text))
    combined = "\n".join(auth_js_parts)

    assert re.search(
        r"\\\$|\$(?:ne|gt|gte|lt|lte|where|regex|or|and)\b|\[[^\]]*\$",
        combined,
        re.IGNORECASE,
    ) or (
        "$" in combined
        and re.search(
            r"\b(?:test|includes|indexOf|match|search)\s*\(|\bRegExp\b", combined
        )
    ), "Expected client-side NoSQL operator validation pattern in auth JS"
    assert re.search(
        r"<script|onerror|onload|javascript:|\[[^\]]*[<>]|\b(?:includes|indexOf|test|match|search)\s*\(\s*['\"][<>]",
        combined,
        re.IGNORECASE,
    ), "Expected client-side XSS validation pattern in auth JS"
    assert re.search(r"\\d\{6\}|\[0-9\]\{6\}", combined), (
        "Expected client-side 6-digit OTP format validation in recuperar JS"
    )
    assert "!==" in combined or "!=" in combined, (
        "Expected password confirmation equality check in recuperar JS"
    )


def _is_initially_hidden(el: dict[str, Any]) -> bool:
    if "hidden" in el or el.get("aria-hidden", "").lower() == "true":
        return True
    classes = set(el.get("class", "").lower().split())
    return bool(classes & {"hidden", "is-hidden", "d-none"})


def test_t2_f7_html_initial_states_bounds_and_no_login_logout_leak(
    client: VIHttpClient, config: E2EConfig
) -> None:
    login_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/login")
    login_insp = login_bundle["inspector"]
    assert not any("Cerrar Sesión" in b.get("text", "") for b in login_insp.buttons)
    assert login_insp.alerts, "Expected role='alert' or aria-live banner on /login"
    assert any(_is_initially_hidden(alert) for alert in login_insp.alerts)

    user_inputs = [
        i for i in login_insp.inputs
        if i.get("type", "text").lower() == "text"
    ]
    pw_inputs = [
        i for i in login_insp.inputs
        if i.get("type", "").lower() == "password"
    ]
    for inp in user_inputs:
        if "maxlength" in inp:
            assert int(inp["maxlength"]) <= 64
    for inp in pw_inputs:
        if "maxlength" in inp:
            assert int(inp["maxlength"]) <= 128

    rec_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/recuperar")
    rec_insp = rec_bundle["inspector"]
    assert not any("Cerrar Sesión" in b.get("text", "") for b in rec_insp.buttons)
    paso2_el = next(
        (
            el for eid, el in rec_insp.elements_by_id.items()
            if re.search(r"(?:paso|step)[-_]?2", eid, re.IGNORECASE)
        ),
        None,
    )
    if paso2_el is not None:
        assert _is_initially_hidden(paso2_el)
    else:
        assert re.search(
            r"<(?:div|section|form|fieldset)\b[^>]*(?:\bhidden\b|class=['\"][^'\"]*\b(?:hidden|is-hidden|d-none)\b)",
            rec_bundle["page"].text,
            re.IGNORECASE,
        ), "Expected Step 2 section on /recuperar to be initially hidden"

    codigo_inputs = [
        i for i in rec_insp.inputs
        if "6 dígitos" in i.get("placeholder", "") or i.get("id") == "codigo"
    ]
    assert codigo_inputs
    assert any(i.get("maxlength") == "6" for i in codigo_inputs)

    mon_bundle = discover_and_fetch_page_bundle(client, config.base_url, "/monitoreo")
    mon_insp = mon_bundle["inspector"]
    btn_map = {b.get("text", ""): b for b in mon_insp.buttons}
    assert any("Iniciar Cámara" in k and "disabled" not in v for k, v in btn_map.items())
    assert any("Dibujar Cerco" in k and "disabled" in v for k, v in btn_map.items())
    assert any("Limpiar Cerco" in k and "disabled" in v for k, v in btn_map.items())
    assert any("APLICAR UMBRALES" in k.upper() and "disabled" in v for k, v in btn_map.items())


def test_t2_f7_security_headers_on_html_and_static_assets(
    client: VIHttpClient, config: E2EConfig
) -> None:
    for route in ("/", "/login", "/recuperar", "/monitoreo"):
        bundle = discover_and_fetch_page_bundle(client, config.base_url, route)
        page_headers = bundle["page"].headers
        assert page_headers.get("x-content-type-options", "").lower() == "nosniff"
        csp = page_headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self'" in csp
        assert (
            page_headers.get("x-frame-options", "").upper() == "DENY"
            or "frame-ancestors 'none'" in csp
        )
        assert page_headers.get("referrer-policy")

        all_texts = [bundle["page"].text]
        for asset_resp in (*bundle["css"].values(), *bundle["js"].values()):
            assert asset_resp.headers.get("x-content-type-options", "").lower() == "nosniff"
            all_texts.append(asset_resp.text)

        for body_text in all_texts:
            assert "MongoDB Atlas" not in body_text
            assert "RepositorioMongoDBAtlas" not in body_text


# ---------------------------------------------------------------------------
# F8: Infrastructure & Seed Boundaries — 5 tests
# ---------------------------------------------------------------------------


def test_t2_f8_unknown_api_route_returns_404_not_500(client: VIHttpClient) -> None:
    resp = client.get("/api/auth/nonexistent")
    assert resp.status_code == 404
    assert resp.headers.get("x-content-type-options", "").lower() == "nosniff"


def test_t2_f8_unknown_page_route_returns_404(client: VIHttpClient) -> None:
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404


def test_t2_f8_case_sensitivity_username_vi(
    client: VIHttpClient, config: E2EConfig
) -> None:
    resp = client.login(config.username.upper(), config.password)
    assert resp.status_code == 401


def test_t2_f8_seed_user_correo_exact_match(
    client: VIHttpClient, config: E2EConfig
) -> None:
    other = client.recuperar_solicitar("other@espe.edu.ec")
    assert other.status_code in (400, 404)

    upper = client.recuperar_solicitar(config.email.upper())
    assert upper.status_code in (200, 400, 404)


def test_t2_f8_container_restart_or_seed_idempotency_check(
    client: VIHttpClient, config: E2EConfig, docker_inspector: DockerInspector
) -> None:
    for _ in range(2):
        r = client.login(config.username, config.password)
        assert r.status_code == 200
        tok = r.json()["token"]
        assert client.logout(tok).status_code == 200

    docs = docker_inspector.query_usuarios_via_mongosh()
    if docs is not None:
        seed_docs = [d for d in docs if d.get("usuario") == config.username]
        assert len(seed_docs) == 1
