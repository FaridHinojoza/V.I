"""Opaque-box E2E test infrastructure and fixtures for Sistema V.I — US-01.

Strict opaque-box rules:
- Uses ONLY Python stdlib + pytest.
- Zero imports from `app`, `pymongo`, `bcrypt`, `jwt`, `pydantic`, or `httpx`.
- Zero disk reads of server static files; all HTML/CSS/JS is fetched over HTTP from `VI_BASE_URL`.
- Zero import-time network or Docker calls (so `pytest tests/e2e --collect-only` works offline).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Iterator, Optional
import urllib.error
import urllib.parse
import urllib.request

import pytest

_UNSET = object()

_OTP_PATTERNS = (
    lambda correo: re.compile(
        rf"RECOVERY_CODE\s+correo={re.escape(correo)}\s+codigo=(\d{{6}})"
    ),
    lambda _correo: re.compile(r"RECOVERY_CODE[^\n\r]*?codigo[=:]\s*(\d{6})"),
    lambda _correo: re.compile(
        r"(?:codigo(?:_recuperacion)?|recovery[_\s]?code|c[oó]digo|OTP)"
        r"[^\n\r\d]{0,40}(\d{6})",
        re.IGNORECASE,
    ),
)

_JS_REGEX_PREV_KEYWORDS = frozenset(
    {
        "return",
        "case",
        "throw",
        "else",
        "do",
        "typeof",
        "void",
        "delete",
        "in",
        "instanceof",
        "new",
        "yield",
        "await",
        "of",
    }
)


def pytest_configure(config: pytest.Config) -> None:
    """Register custom markers and document sequential single-session constraint."""
    config.addinivalue_line(
        "markers",
        "e2e_single_session: Exercises US-01 unique non-recurrent session; run sequentially.",
    )


@dataclass(frozen=True)
class E2EConfig:
    """Runtime configuration for opaque-box E2E tests."""

    base_url: str
    username: str
    email: str
    password: str
    timeout: float
    compose_project: str
    app_container: str
    mongo_container: str
    mongo_db: str
    docker_checks: bool
    skip_browser: bool
    require_browser: bool
    recovery_code_override: str
    log_file: str
    repo_root: Path

    @classmethod
    def from_env(cls) -> "E2EConfig":
        return cls(
            base_url=os.getenv("VI_BASE_URL", "http://127.0.0.1:8000").rstrip("/"),
            username=os.getenv("VI_USERNAME", "vi"),
            email=os.getenv("VI_EMAIL", "dsceli@espe.edu.ec"),
            password=os.getenv("VI_PASSWORD", "OperadorVI2026*"),
            timeout=float(os.getenv("VI_HTTP_TIMEOUT", "10.0")),
            compose_project=os.getenv("VI_COMPOSE_PROJECT", ""),
            app_container=os.getenv("VI_APP_CONTAINER", ""),
            mongo_container=os.getenv("VI_MONGO_CONTAINER", ""),
            mongo_db=os.getenv("VI_MONGO_DB", "vi_db"),
            docker_checks=os.getenv("VI_DOCKER_CHECKS", "1") != "0",
            skip_browser=os.getenv("VI_SKIP_BROWSER", "0") == "1",
            require_browser=os.getenv("VI_REQUIRE_BROWSER", "0") == "1",
            recovery_code_override=os.getenv("VI_RECOVERY_CODE", "").strip(),
            log_file=os.getenv("VI_LOG_FILE", "").strip(),
            repo_root=Path(__file__).resolve().parents[2],
        )


@dataclass
class HttpResponse:
    """Captured HTTP response (including 4xx/5xx error responses)."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    url: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent urllib from following HTTP 3xx redirects automatically."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class VIHttpClient:
    """Stdlib-only HTTP client with automatic single-session JWT cleanup tracking."""

    def __init__(self, config: E2EConfig) -> None:
        self.config = config
        self._tracked_tokens: list[str] = []

    @property
    def tracked_tokens(self) -> tuple[str, ...]:
        return tuple(self._tracked_tokens)

    def track_token(self, token: str) -> None:
        if token and token not in self._tracked_tokens:
            self._tracked_tokens.append(token)

    def untrack_token(self, token: str) -> None:
        if token in self._tracked_tokens:
            self._tracked_tokens.remove(token)

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.config.base_url}{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = _UNSET,
        raw_body: Optional[bytes] = None,
        headers: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        url = self._build_url(path)
        req_headers: dict[str, str] = {}
        if headers:
            req_headers.update(headers)

        data: Optional[bytes] = raw_body
        if json_body is not _UNSET:
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            if not any(k.lower() == "content-type" for k in req_headers):
                req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(
            url,
            data=data,
            headers=req_headers,
            method=method.upper(),
        )
        opener = (
            urllib.request.build_opener()
            if follow_redirects
            else urllib.request.build_opener(_NoRedirectHandler())
        )
        effective_timeout = timeout if timeout is not None else self.config.timeout

        try:
            with opener.open(req, timeout=effective_timeout) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                body = resp.read() or b""
                http_resp = HttpResponse(
                    status_code=int(resp.status),
                    headers=resp_headers,
                    body=body,
                    url=str(resp.geturl() or url),
                )
        except urllib.error.HTTPError as exc:
            resp_headers = {k.lower(): v for k, v in exc.headers.items()}
            body = exc.read() or b""
            http_resp = HttpResponse(
                status_code=int(exc.code),
                headers=resp_headers,
                body=body,
                url=str(exc.geturl() or url),
            )

        parsed_path = urllib.parse.urlparse(url).path.rstrip("/")
        if (
            method.upper() == "POST"
            and parsed_path == "/api/auth/login"
            and http_resp.status_code == 200
        ):
            try:
                payload = http_resp.json()
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                token = payload.get("token")
                if isinstance(token, str) and token:
                    self.track_token(token)

        return http_resp

    def get(
        self,
        path: str,
        *,
        headers: Optional[dict[str, str]] = None,
        follow_redirects: bool = True,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        return self.request(
            "GET",
            path,
            headers=headers,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def post_json(
        self,
        path: str,
        payload: Any,
        *,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        return self.request(
            "POST",
            path,
            json_body=payload,
            headers=headers,
            timeout=timeout,
        )

    def post_raw(
        self,
        path: str,
        raw_bytes: bytes,
        *,
        content_type: str = "application/json",
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        req_headers = {"Content-Type": content_type}
        if headers:
            req_headers.update(headers)
        return self.request(
            "POST",
            path,
            raw_body=raw_bytes,
            headers=req_headers,
            timeout=timeout,
        )

    def login(self, usuario: str, clave: str) -> HttpResponse:
        return self.post_json("/api/auth/login", {"usuario": usuario, "clave": clave})

    def logout(
        self,
        token: Optional[str] = None,
        *,
        via_body: bool = False,
        via_both: bool = False,
    ) -> HttpResponse:
        req_headers: dict[str, str] = {}
        if token is None:
            return self.request("POST", "/api/auth/logout", raw_body=b"")
        if via_both:
            req_headers["Authorization"] = f"Bearer {token}"
            return self.post_json("/api/auth/logout", {"token": token}, headers=req_headers)
        if via_body:
            return self.post_json("/api/auth/logout", {"token": token})
        req_headers["Authorization"] = f"Bearer {token}"
        return self.request("POST", "/api/auth/logout", raw_body=b"", headers=req_headers)

    def verificar(
        self,
        token: Optional[str] = None,
        *,
        path: str = "/api/auth/verificar",
        scheme: str = "Bearer",
    ) -> HttpResponse:
        req_headers: dict[str, str] = {}
        if token is not None:
            if scheme:
                req_headers["Authorization"] = f"{scheme} {token}"
            else:
                req_headers["Authorization"] = token
        return self.get(path, headers=req_headers)

    def recuperar_solicitar(self, correo: str) -> HttpResponse:
        return self.post_json(
            "/api/auth/recuperar",
            {"accion": "solicitar_codigo", "correo": correo},
        )

    def recuperar_actualizar(
        self,
        correo: str,
        codigo: str,
        nueva_clave: str,
        confirmar_clave: str,
    ) -> HttpResponse:
        return self.post_json(
            "/api/auth/recuperar",
            {
                "accion": "actualizar_clave",
                "correo": correo,
                "codigo": codigo,
                "nueva_clave": nueva_clave,
                "confirmar_clave": confirmar_clave,
            },
        )

    def cleanup_sessions(self) -> None:
        """Best-effort teardown releasing any tracked JWTs."""
        for token in reversed(list(self._tracked_tokens)):
            try:
                self.logout(token)
            except (urllib.error.URLError, OSError):
                pass
            finally:
                self.untrack_token(token)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_jwt_payload_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode JWT header and payload using Python stdlib only (no signature check)."""
    parts = token.split(".")
    if len(parts) != 3 or any(not p for p in parts):
        raise ValueError(f"Expected 3 non-empty JWT segments, got {len(parts)}")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    return header, payload


@dataclass(frozen=True)
class LogBaseline:
    """Snapshot of app log state captured immediately before a Step 1 request."""

    since_utc: datetime
    file_offset: Optional[int] = None
    stdout_match_count: int = 0
    stderr_match_count: int = 0
    stdout_anchor: str = ""
    stderr_anchor: str = ""


def _extract_otp_matches_ordered(text: str, correo: str) -> list[str]:
    """Return all 6-digit OTP matches for `correo` ordered by match end-position."""
    if not text:
        return []
    candidates: dict[tuple[int, int], str] = {}
    correo_lower = correo.strip().lower()
    for build_pattern in _OTP_PATTERNS:
        pattern = build_pattern(correo)
        for match in pattern.finditer(text):
            code = match.group(1)
            code_span = (match.start(1), match.end(1))
            line_start = text.rfind("\n", 0, match.start()) + 1
            line_end = text.find("\n", match.end())
            if line_end == -1:
                line_end = len(text)
            line = text[line_start:line_end]
            email_match = re.search(r"correo\s*=\s*([^\s,;]+)", line, re.IGNORECASE)
            if email_match and email_match.group(1).strip().lower() != correo_lower:
                continue
            candidates[code_span] = str(code)
    return [candidates[span] for span in sorted(candidates, key=lambda s: (s[1], s[0]))]


def _extract_last_otp_from_text(text: str, correo: str) -> Optional[str]:
    matches = _extract_otp_matches_ordered(text, correo)
    return matches[-1] if matches else None


def _run_cmd(
    args: list[str],
    *,
    cwd: Optional[Path] = None,
    timeout: float = 10.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _discover_app_container(config: E2EConfig) -> Optional[str]:
    if config.app_container:
        return config.app_container
    if not shutil.which("docker"):
        return None
    proc = _run_cmd(["docker", "ps", "--format", "{{.Names}}"], timeout=5.0)
    if proc.returncode != 0:
        return None
    names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    for name in names:
        if re.search(r"vi[-_]?app", name, re.IGNORECASE):
            return name
    return None


def _discover_mongo_container(config: E2EConfig) -> Optional[str]:
    if config.mongo_container:
        return config.mongo_container
    if not shutil.which("docker"):
        return None
    proc = _run_cmd(["docker", "ps", "--format", "{{.Names}}"], timeout=5.0)
    if proc.returncode != 0:
        return None
    names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    for name in names:
        if re.search(r"mongo", name, re.IGNORECASE):
            return name
    return None


def _compose_base_cmd(config: E2EConfig) -> list[str]:
    cmd = ["docker", "compose"]
    if config.compose_project:
        cmd.extend(["-p", config.compose_project])
    return cmd


def _read_app_logs_streams(
    config: E2EConfig, since_utc: Optional[datetime] = None, *, tail: int = 500
) -> tuple[str, str]:
    if not shutil.which("docker"):
        return "", ""
    since_args: list[str] = []
    if since_utc is not None:
        since_args = ["--since", since_utc.strftime("%Y-%m-%dT%H:%M:%SZ")]

    if config.app_container:
        proc = _run_cmd(
            ["docker", "logs", *since_args, "--tail", str(tail), config.app_container],
            timeout=6.0,
        )
        return (proc.stdout or ""), (proc.stderr or "")

    compose_file = config.repo_root / "docker-compose.yml"
    if compose_file.exists():
        cmd = [
            *_compose_base_cmd(config),
            "logs",
            "--no-color",
            *since_args,
            "--tail",
            str(tail),
            "vi-app",
        ]
        proc = _run_cmd(cmd, cwd=config.repo_root, timeout=6.0)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        if proc.returncode == 0 and (stdout.strip() or stderr.strip()):
            return stdout, stderr

    discovered = _discover_app_container(config)
    if discovered:
        proc = _run_cmd(
            ["docker", "logs", *since_args, "--tail", str(tail), discovered],
            timeout=6.0,
        )
        return (proc.stdout or ""), (proc.stderr or "")
    return "", ""


def _read_app_logs(config: E2EConfig, since_utc: Optional[datetime]) -> str:
    stdout, stderr = _read_app_logs_streams(config, since_utc=since_utc, tail=200)
    if not stdout and not stderr:
        return ""
    return stdout + "\n" + stderr


def capture_log_baseline(
    config: E2EConfig, correo: Optional[str] = None
) -> LogBaseline:
    """Capture current log offset / match counts before triggering recovery Step 1."""
    target_correo = correo or config.email
    now_utc = datetime.now(timezone.utc)
    if config.recovery_code_override and re.fullmatch(
        r"\d{6}", config.recovery_code_override
    ):
        return LogBaseline(since_utc=now_utc)

    if config.log_file:
        log_path = Path(config.log_file)
        offset = len(log_path.read_bytes()) if log_path.exists() else 0
        return LogBaseline(since_utc=now_utc, file_offset=offset)

    stdout, stderr = _read_app_logs_streams(config, since_utc=None, tail=500)
    stdout_matches = _extract_otp_matches_ordered(stdout, target_correo)
    stderr_matches = _extract_otp_matches_ordered(stderr, target_correo)
    return LogBaseline(
        since_utc=now_utc,
        stdout_match_count=len(stdout_matches),
        stderr_match_count=len(stderr_matches),
        stdout_anchor=stdout[-300:],
        stderr_anchor=stderr[-300:],
    )


def _extract_new_otp_from_stream(
    text: str, correo: str, prior_count: int, anchor: str
) -> Optional[str]:
    if not text:
        return None
    if anchor:
        idx = text.rfind(anchor)
        if idx != -1:
            delta = text[idx + len(anchor) :]
            return _extract_last_otp_from_text(delta, correo)
        # Anchor rolled past --tail window: all visible matches are newer than baseline.
        return _extract_last_otp_from_text(text, correo)
    matches = _extract_otp_matches_ordered(text, correo)
    if len(matches) > prior_count:
        return matches[prior_count:][-1]
    return None


def extract_recovery_code(
    config: E2EConfig,
    correo: str,
    *,
    since_utc: Optional[datetime] = None,
    baseline: Optional[LogBaseline] = None,
    timeout: float = 6.0,
) -> str:
    """Extract the newest 6-digit recovery OTP strictly after `baseline` (if given)."""
    if config.recovery_code_override and re.fullmatch(
        r"\d{6}", config.recovery_code_override
    ):
        return config.recovery_code_override

    if config.log_file:
        log_path = Path(config.log_file)
        deadline = time.monotonic() + timeout
        last_text = ""
        while time.monotonic() <= deadline:
            if log_path.exists():
                raw_bytes = log_path.read_bytes()
                if baseline is not None and baseline.file_offset is not None:
                    if len(raw_bytes) >= baseline.file_offset:
                        delta_bytes = raw_bytes[baseline.file_offset :]
                    else:
                        delta_bytes = raw_bytes
                    last_text = delta_bytes.decode("utf-8", errors="replace")
                else:
                    last_text = raw_bytes.decode("utf-8", errors="replace")
                otp = _extract_last_otp_from_text(last_text, correo)
                if otp:
                    return otp
            time.sleep(0.25)
        raise AssertionError(
            f"Recovery OTP for {correo!r} not found in VI_LOG_FILE={log_path}. "
            f"Tail:\n{last_text[-800:]}"
        )

    deadline = time.monotonic() + timeout
    last_logs = ""
    while time.monotonic() <= deadline:
        if baseline is not None:
            stdout, stderr = _read_app_logs_streams(config, since_utc=None, tail=500)
            last_logs = (stdout + "\n" + stderr).strip()
            otp = _extract_new_otp_from_stream(
                stdout, correo, baseline.stdout_match_count, baseline.stdout_anchor
            )
            if not otp:
                otp = _extract_new_otp_from_stream(
                    stderr, correo, baseline.stderr_match_count, baseline.stderr_anchor
                )
            if otp:
                return otp
        else:
            last_logs = _read_app_logs(config, since_utc)
            if last_logs:
                otp = _extract_last_otp_from_text(last_logs, correo)
                if otp:
                    return otp
        time.sleep(0.3)

    raise AssertionError(
        f"Recovery OTP for {correo!r} not found within {timeout:.1f}s via Docker logs "
        f"(set VI_RECOVERY_CODE or VI_LOG_FILE if running outside Docker). "
        f"Log tail:\n{last_logs[-800:]}"
    )


class HTMLAssetInspector(HTMLParser):
    """Stdlib HTML parser extracting links, scripts, forms, inputs, buttons, and text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stylesheets: list[str] = []
        self.all_links: list[dict[str, str]] = []
        self.external_scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.inline_styles: list[str] = []
        self.inline_event_attrs: list[tuple[str, str]] = []
        self.headings: list[tuple[str, str]] = []
        self.inputs: list[dict[str, Any]] = []
        self.buttons: list[dict[str, Any]] = []
        self.anchors: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.elements_by_id: dict[str, dict[str, Any]] = {}
        self._visible_chunks: list[str] = []

        self._in_script = False
        self._script_has_src = False
        self._script_buf: list[str] = []

        self._in_style = False
        self._style_buf: list[str] = []

        self._heading_tag: Optional[str] = None
        self._heading_buf: list[str] = []

        self._in_button = False
        self._button_attrs: dict[str, Any] = {}
        self._button_buf: list[str] = []

        self._in_anchor = False
        self._anchor_attrs: dict[str, Any] = {}
        self._anchor_buf: list[str] = []

    @property
    def visible_text(self) -> str:
        return " ".join(" ".join(self._visible_chunks).split())

    def _record_attrs(
        self, tag: str, attrs_list: list[tuple[str, Optional[str]]]
    ) -> dict[str, Any]:
        attr_dict: dict[str, Any] = {}
        for raw_name, raw_val in attrs_list:
            name = raw_name.lower()
            val = "" if raw_val is None else raw_val
            attr_dict[name] = val
            if name.startswith("on"):
                self.inline_event_attrs.append((tag, name))
        elem_id = attr_dict.get("id")
        if elem_id:
            self.elements_by_id[elem_id] = {"tag": tag, **attr_dict}
        if (
            attr_dict.get("role", "").lower() == "alert"
            or attr_dict.get("aria-live", "").lower() in ("polite", "assertive")
        ):
            self.alerts.append({"tag": tag, **attr_dict})
        return attr_dict

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, Optional[str]]]
    ) -> None:
        tag_l = tag.lower()
        attr_dict = self._record_attrs(tag_l, attrs)

        if tag_l == "link":
            href = attr_dict.get("href", "")
            rel = attr_dict.get("rel", "")
            self.all_links.append({"rel": rel, "href": href})
            if "stylesheet" in rel.lower().split() and href:
                self.stylesheets.append(href)
        elif tag_l == "script":
            self._in_script = True
            self._script_buf = []
            src = attr_dict.get("src", "")
            self._script_has_src = bool(src)
            if src:
                self.external_scripts.append(src)
        elif tag_l == "style":
            self._in_style = True
            self._style_buf = []
        elif tag_l in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading_tag = tag_l
            self._heading_buf = []
        elif tag_l == "input":
            self.inputs.append(attr_dict)
        elif tag_l == "button":
            self._in_button = True
            self._button_attrs = attr_dict
            self._button_buf = []
        elif tag_l == "a":
            self._in_anchor = True
            self._anchor_attrs = attr_dict
            self._anchor_buf = []

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, Optional[str]]]
    ) -> None:
        tag_l = tag.lower()
        attr_dict = self._record_attrs(tag_l, attrs)
        if tag_l == "link":
            href = attr_dict.get("href", "")
            rel = attr_dict.get("rel", "")
            self.all_links.append({"rel": rel, "href": href})
            if "stylesheet" in rel.lower().split() and href:
                self.stylesheets.append(href)
        elif tag_l == "input":
            self.inputs.append(attr_dict)

    def handle_endtag(self, tag: str) -> None:
        tag_l = tag.lower()
        if tag_l == "script" and self._in_script:
            content = "".join(self._script_buf).strip()
            if not self._script_has_src and content:
                self.inline_scripts.append(content)
            self._in_script = False
            self._script_has_src = False
            self._script_buf = []
        elif tag_l == "style" and self._in_style:
            content = "".join(self._style_buf).strip()
            if content:
                self.inline_styles.append(content)
            self._in_style = False
            self._style_buf = []
        elif tag_l == self._heading_tag:
            text = " ".join("".join(self._heading_buf).split())
            self.headings.append((tag_l, text))
            self._heading_tag = None
            self._heading_buf = []
        elif tag_l == "button" and self._in_button:
            text = " ".join("".join(self._button_buf).split())
            self.buttons.append({**self._button_attrs, "text": text})
            self._in_button = False
            self._button_attrs = {}
            self._button_buf = []
        elif tag_l == "a" and self._in_anchor:
            text = " ".join("".join(self._anchor_buf).split())
            self.anchors.append({**self._anchor_attrs, "text": text})
            self._in_anchor = False
            self._anchor_attrs = {}
            self._anchor_buf = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_buf.append(data)
            return
        if self._in_style:
            self._style_buf.append(data)
            return
        self._visible_chunks.append(data)
        if self._heading_tag:
            self._heading_buf.append(data)
        if self._in_button:
            self._button_buf.append(data)
        if self._in_anchor:
            self._anchor_buf.append(data)


def strip_css_comments(css_text: str) -> str:
    """Remove /* ... */ CSS comments."""
    return re.sub(r"/\*[\s\S]*?\*/", "", css_text)


def extract_css_custom_properties(css_text: str) -> dict[str, str]:
    """Extract CSS `--custom-prop: value;` declarations (lowercased keys/values)."""
    props: dict[str, str] = {}
    for name, value in re.findall(
        r"(--[a-z0-9_-]+)\s*:\s*([^;}{]+)", css_text, re.IGNORECASE
    ):
        props[name.strip().lower()] = value.strip().lower()
    return props


def resolve_css_vars(value: str, props: dict[str, str], depth: int = 4) -> str:
    """Resolve `var(--name[, fallback])` references using extracted CSS properties."""
    resolved = value
    for _ in range(depth):
        def _sub(match: re.Match[str]) -> str:
            var_name = match.group(1).strip().lower()
            fallback = match.group(2).strip() if match.group(2) else ""
            return props.get(var_name, fallback or match.group(0))

        next_val = re.sub(
            r"var\(\s*(--[a-z0-9_-]+)\s*(?:,\s*([^)]+))?\)",
            _sub,
            resolved,
            flags=re.IGNORECASE,
        )
        if next_val == resolved:
            break
        resolved = next_val
    return resolved


def strip_js_comments(js_text: str) -> str:
    """Remove // and /* ... */ JS comments while preserving strings, templates, and regex literals."""
    out: list[str] = []
    n = len(js_text)
    i = 0
    regex_allowed = True
    template_brace_stack: list[int] = []
    in_template_text = False

    while i < n:
        if in_template_text:
            ch = js_text[i]
            if ch == "\\" and i + 1 < n:
                out.append(js_text[i : i + 2])
                i += 2
                continue
            if ch == "$" and i + 1 < n and js_text[i + 1] == "{":
                out.append("${")
                i += 2
                in_template_text = False
                template_brace_stack.append(1)
                regex_allowed = True
                continue
            out.append(ch)
            i += 1
            if ch == "`":
                in_template_text = False
                regex_allowed = False
            continue

        ch = js_text[i]

        if ch in " \t\r\n\f\v":
            out.append(ch)
            i += 1
            continue

        if ch == "/" and i + 1 < n and js_text[i + 1] == "/":
            i += 2
            while i < n and js_text[i] not in "\r\n":
                i += 1
            out.append(" ")
            continue

        if ch == "/" and i + 1 < n and js_text[i + 1] == "*":
            end = js_text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
            continue

        if ch in ("'", '"'):
            quote = ch
            start = i
            i += 1
            while i < n:
                c = js_text[i]
                if c == "\\" and i + 1 < n:
                    i += 2
                    continue
                i += 1
                if c == quote:
                    break
            out.append(js_text[start:i])
            regex_allowed = False
            continue

        if ch == "`":
            out.append("`")
            i += 1
            in_template_text = True
            continue

        if ch == "/" and regex_allowed:
            start = i
            j = i + 1
            in_char_class = False
            closed = False
            while j < n:
                c = js_text[j]
                if c in "\r\n":
                    break
                if c == "\\" and j + 1 < n and js_text[j + 1] not in "\r\n":
                    j += 2
                    continue
                if c == "[" and not in_char_class:
                    in_char_class = True
                    j += 1
                    continue
                if c == "]" and in_char_class:
                    in_char_class = False
                    j += 1
                    continue
                if c == "/" and not in_char_class:
                    j += 1
                    while j < n and js_text[j].isalpha():
                        j += 1
                    closed = True
                    break
                j += 1
            if closed:
                out.append(js_text[start:j])
                i = j
                regex_allowed = False
                continue
            out.append("/")
            i += 1
            regex_allowed = True
            continue

        if ch == "{":
            if template_brace_stack:
                template_brace_stack[-1] += 1
            out.append(ch)
            i += 1
            regex_allowed = True
            continue

        if ch == "}":
            if template_brace_stack:
                template_brace_stack[-1] -= 1
                if template_brace_stack[-1] == 0:
                    template_brace_stack.pop()
                    out.append(ch)
                    i += 1
                    in_template_text = True
                    continue
            out.append(ch)
            i += 1
            regex_allowed = True
            continue

        if ch.isalpha() or ch in ("_", "$"):
            start = i
            i += 1
            while i < n and (js_text[i].isalnum() or js_text[i] in ("_", "$")):
                i += 1
            ident = js_text[start:i]
            out.append(ident)
            prev_char = js_text[start - 1] if start > 0 else ""
            if ident in _JS_REGEX_PREV_KEYWORDS and prev_char != ".":
                regex_allowed = True
            else:
                regex_allowed = False
            continue

        if ch.isdigit():
            start = i
            i += 1
            while i < n and (js_text[i].isalnum() or js_text[i] in (".", "_")):
                i += 1
            out.append(js_text[start:i])
            regex_allowed = False
            continue

        if js_text[i : i + 2] in ("++", "--"):
            out.append(js_text[i : i + 2])
            i += 2
            regex_allowed = False
            continue

        out.append(ch)
        i += 1
        if ch in (")", "]"):
            regex_allowed = False
        else:
            regex_allowed = True

    return "".join(out)


def is_same_origin(base_url: str, candidate_url: str) -> bool:
    base_p = urllib.parse.urlparse(base_url)
    cand_p = urllib.parse.urlparse(candidate_url)
    return cand_p.scheme == base_p.scheme and cand_p.netloc == base_p.netloc


def _extract_css_imports(css_text: str) -> list[str]:
    clean = strip_css_comments(css_text)
    return re.findall(
        r"""@import\s+(?:url\(\s*['"]?([^'")\s]+)['"]?\s*\)|['"]([^'"]+)['"])""",
        clean,
        flags=re.IGNORECASE,
    )


def discover_and_fetch_page_bundle(
    client: VIHttpClient,
    base_url: str,
    path: str,
) -> dict[str, Any]:
    """Fetch an HTML page and crawl its same-origin CSS/JS assets purely over HTTP."""
    page_resp = client.get(path)
    assert page_resp.status_code == 200, (
        f"Expected 200 OK for GET {path}, got {page_resp.status_code}"
    )
    inspector = HTMLAssetInspector()
    inspector.feed(page_resp.text)
    inspector.close()

    page_url = urllib.parse.urljoin(f"{base_url}/", path.lstrip("/"))
    css_assets: dict[str, HttpResponse] = {}
    js_assets: dict[str, HttpResponse] = {}
    external_urls: list[str] = []

    pending_css: list[tuple[str, str]] = [
        (page_url, href) for href in inspector.stylesheets
    ]
    visited_css: set[str] = set()
    while pending_css:
        parent_url, href = pending_css.pop(0)
        resolved = urllib.parse.urljoin(parent_url, href)
        if not is_same_origin(base_url, resolved):
            external_urls.append(resolved)
            continue
        if resolved in visited_css:
            continue
        visited_css.add(resolved)
        asset_resp = client.get(resolved)
        css_assets[resolved] = asset_resp
        if asset_resp.status_code == 200:
            for url_match, str_match in _extract_css_imports(asset_resp.text):
                imp_ref = url_match or str_match
                if imp_ref:
                    pending_css.append((resolved, imp_ref))

    for src in inspector.external_scripts:
        resolved = urllib.parse.urljoin(page_url, src)
        if not is_same_origin(base_url, resolved):
            external_urls.append(resolved)
            continue
        if resolved not in js_assets:
            js_assets[resolved] = client.get(resolved)

    return {
        "path": path,
        "page_url": page_url,
        "page": page_resp,
        "inspector": inspector,
        "css": css_assets,
        "js": js_assets,
        "external_urls": external_urls,
    }


def find_optional_browser_and_node(config: E2EConfig) -> dict[str, Optional[str]]:
    """Locate optional Node.js and headless Edge/Chromium binaries on the host."""
    node_bin = shutil.which("node")
    browser_bin: Optional[str] = None
    if not config.skip_browser:
        candidates = [
            shutil.which("msedge"),
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            shutil.which("chromium"),
            shutil.which("chromium-browser"),
            shutil.which("google-chrome"),
        ]
        for candidate in candidates:
            if candidate and Path(candidate).exists():
                browser_bin = candidate
                break
    return {"node": node_bin, "browser": browser_bin}


@dataclass
class DockerInspector:
    """Opaque-box Docker Compose and MongoDB CLI inspection helper."""

    config: E2EConfig

    @property
    def enabled(self) -> bool:
        return self.config.docker_checks

    @property
    def cli_available(self) -> bool:
        return bool(self.config.docker_checks and shutil.which("docker"))

    @property
    def compose_file_path(self) -> Path:
        return self.config.repo_root / "docker-compose.yml"

    def read_compose_file(self) -> Optional[str]:
        if self.compose_file_path.exists():
            return self.compose_file_path.read_text(encoding="utf-8", errors="replace")
        return None

    def get_compose_ps(self) -> list[dict[str, Any]]:
        if not self.cli_available or not self.compose_file_path.exists():
            return []
        proc = _run_cmd(
            [*_compose_base_cmd(self.config), "ps", "--format", "json"],
            cwd=self.config.repo_root,
            timeout=10.0,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        raw = proc.stdout.strip()
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except ValueError:
            items: list[dict[str, Any]] = []
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        items.append(obj)
                except ValueError:
                    continue
            return items
        return []

    def query_usuarios_via_mongosh(self) -> Optional[list[dict[str, Any]]]:
        if not self.cli_available:
            return None
        js_eval = (
            f"JSON.stringify(db.getSiblingDB({json.dumps(self.config.mongo_db)})"
            ".usuarios.find({}, {_id: 0, usuario: 1, correo: 1, password_hash: 1, "
            "password: 1, token_sesion_unica: 1, codigo_recuperacion: 1}).toArray())"
        )
        if self.compose_file_path.exists() and not self.config.mongo_container:
            proc = _run_cmd(
                [
                    *_compose_base_cmd(self.config),
                    "exec",
                    "-T",
                    "mongodb",
                    "mongosh",
                    "--quiet",
                    "--eval",
                    js_eval,
                ],
                cwd=self.config.repo_root,
                timeout=10.0,
            )
        else:
            mongo_name = _discover_mongo_container(self.config)
            if not mongo_name:
                return None
            proc = _run_cmd(
                ["docker", "exec", mongo_name, "mongosh", "--quiet", "--eval", js_eval],
                timeout=10.0,
            )
        if proc.returncode != 0:
            return None
        for line in reversed(proc.stdout.splitlines()):
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                try:
                    data = json.loads(line)
                    if isinstance(data, list):
                        return data
                except ValueError:
                    pass
        return None


@pytest.fixture(scope="session")
def config() -> E2EConfig:
    return E2EConfig.from_env()


@pytest.fixture(scope="session")
def live_server(config: E2EConfig) -> None:
    """Verify the target HTTP server is reachable once tests begin executing."""
    probe_url = f"{config.base_url}/login"
    last_error: Optional[Exception] = None
    for attempt in range(2):
        try:
            req = urllib.request.Request(probe_url, method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if int(resp.status) < 500:
                    return
        except urllib.error.HTTPError as exc:
            if int(exc.code) < 500:
                return
            last_error = exc
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        if attempt == 0:
            time.sleep(0.5)

    msg = (
        f"Target Sistema V.I server unreachable at {config.base_url} "
        f"(last error: {last_error!r}). Start the stack via `docker compose up --build -d` "
        f"or set VI_BASE_URL."
    )
    pytest.fail(msg)


@pytest.fixture(scope="function")
def client(config: E2EConfig, live_server: None) -> Iterator[VIHttpClient]:
    """Yield an opaque-box HTTP client and release any acquired single-session JWTs."""
    http_client = VIHttpClient(config)
    try:
        yield http_client
    finally:
        http_client.cleanup_sessions()


@pytest.fixture(scope="function")
def auth_session(client: VIHttpClient, config: E2EConfig) -> tuple[VIHttpClient, str]:
    """Authenticate the unique seed operator and yield `(client, token)`."""
    resp = client.login(config.username, config.password)
    assert resp.status_code == 200, (
        f"Expected 200 on seed login, got {resp.status_code}: {resp.text}"
    )
    data = resp.json()
    token = data.get("token", "")
    assert isinstance(token, str) and token, f"Missing JWT token in login response: {data}"
    return client, token


@pytest.fixture(scope="function")
def log_baseline(config: E2EConfig):
    """Return a callable `baseline(correo=None)` capturing log state before Step 1."""

    def _capture(correo: Optional[str] = None) -> LogBaseline:
        return capture_log_baseline(config, correo or config.email)

    return _capture


@pytest.fixture(scope="function")
def otp_extractor(config: E2EConfig):
    """Return a callable `extract(correo=..., since_utc=..., baseline=..., timeout=6.0)`."""

    def _extract(
        correo: Optional[str] = None,
        *,
        since_utc: Optional[datetime] = None,
        baseline: Optional[LogBaseline] = None,
        timeout: float = 6.0,
    ) -> str:
        return extract_recovery_code(
            config,
            correo or config.email,
            since_utc=since_utc,
            baseline=baseline,
            timeout=timeout,
        )

    return _extract


@pytest.fixture(scope="function")
def password_restorer(client: VIHttpClient, config: E2EConfig) -> Iterator[None]:
    """Guarantee seed password is restored to `config.password` even if a test fails."""
    try:
        yield
    finally:
        client.cleanup_sessions()
        check = client.login(config.username, config.password)
        if check.status_code == 200:
            client.cleanup_sessions()
        else:
            baseline = capture_log_baseline(config, config.email)
            step1 = client.recuperar_solicitar(config.email)
            if step1.status_code == 200:
                otp = extract_recovery_code(
                    config, config.email, baseline=baseline, timeout=8.0
                )
                step2 = client.recuperar_actualizar(
                    config.email, otp, config.password, config.password
                )
                assert step2.status_code == 200, (
                    f"password_restorer failed during Step 2: "
                    f"{step2.status_code} {step2.text}"
                )
                verify = client.login(config.username, config.password)
                assert verify.status_code == 200, (
                    f"password_restorer could not re-login after restore: "
                    f"{verify.status_code} {verify.text}"
                )
                client.cleanup_sessions()
            else:
                raise AssertionError(
                    f"password_restorer Step 1 failed: {step1.status_code} {step1.text}"
                )


@pytest.fixture(scope="session")
def docker_inspector(config: E2EConfig) -> DockerInspector:
    return DockerInspector(config)
