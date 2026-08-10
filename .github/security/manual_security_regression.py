#!/usr/bin/env python3
"""Repeatable, local-only checks derived from the manual security test plan.

The checks intentionally target the Docker service on localhost. They do not
modify application data. Findings are written to security-reports and the
process exits non-zero when a weakness is observed; the workflow may choose to
continue so that all reports are still uploaded.
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


BASE_URL = os.environ.get("SECURITY_BASE_URL", "http://127.0.0.1:8082").rstrip("/")
REPORT_DIR = Path(os.environ.get("SECURITY_REPORT_DIR", "security-reports"))
MAX_BODY_BYTES = 1024 * 1024

checks: List[Dict[str, object]] = []
findings: List[Dict[str, object]] = []
errors: List[Dict[str, str]] = []


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        return None


OPENER = build_opener(NoRedirect())


def add_check(name: str, status: str, details: str) -> None:
    checks.append({"name": name, "status": status, "details": details})


def add_finding(
    finding_id: str, title: str, severity: str, details: str, docx_mapping: str
) -> None:
    findings.append(
        {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "details": details,
            "docx_mapping": docx_mapping,
        }
    )


def response_body(response) -> str:  # type: ignore[no-untyped-def]
    try:
        return response.read(MAX_BODY_BYTES).decode("utf-8", errors="replace")
    except Exception:
        return ""


def request(
    method: str,
    path: str,
    form: Optional[Dict[str, str]] = None,
    cookie: Optional[str] = None,
) -> Tuple[int, object, str]:
    url = urljoin(BASE_URL + "/", path.lstrip("/"))
    headers = {"User-Agent": "courier-security-regression/1.0"}
    data = None
    if form is not None:
        data = urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie

    req = Request(url, data=data, headers=headers, method=method)
    try:
        response = OPENER.open(req, timeout=20)
        return response.status, response.headers, response_body(response)
    except HTTPError as exc:
        return exc.code, exc.headers, response_body(exc)
    except URLError as exc:
        raise RuntimeError(f"request to {url} failed: {exc.reason}") from exc


def set_cookie_headers(headers: object) -> List[str]:
    get_all = getattr(headers, "get_all", None)
    if not callable(get_all):
        return []
    return list(get_all("Set-Cookie") or [])


def session_cookie(headers: object) -> Optional[Tuple[str, str]]:
    for value in set_cookie_headers(headers):
        match = re.search(r"(?:^|;\s*)PHPSESSID=([^;]+)", value, re.IGNORECASE)
        if match:
            return "PHPSESSID", match.group(1)
    return None


def admin_page_is_accessible(status: int, headers: object, body: str) -> bool:
    if status in (401, 403):
        return False
    location = str(getattr(headers, "get", lambda *_: "")("Location", ""))
    if status in (301, 302, 303, 307, 308) and "login.php" in location.lower():
        return False
    if status != 200:
        return False
    return not re.search(r"sign\s*in|login\.php", body, re.IGNORECASE)


def check_target() -> None:
    parsed = urlparse(BASE_URL)
    if parsed.scheme not in ("http", "https"):
        raise RuntimeError("SECURITY_BASE_URL must use http or https")
    if parsed.hostname not in ("127.0.0.1", "localhost") and os.environ.get(
        "SECURITY_ALLOW_NONLOCAL_TARGET"
    ) != "1":
        raise RuntimeError(
            "Refusing a non-local target; set SECURITY_ALLOW_NONLOCAL_TARGET=1 only for an explicitly approved test environment"
        )

    status, _, _ = request("GET", "/")
    if status >= 500 or status == 0:
        raise RuntimeError(f"application health check returned HTTP {status}")
    add_check("application-available", "passed", f"GET / returned HTTP {status}")


def check_sql_injection() -> None:
    payload = "' OR '1' = '1' -- "
    status, _, body = request(
        "POST",
        "/server/api.php?function_code=login",
        {"email": payload, "password": "manual-regression-invalid"},
    )
    role = body.strip().lower()
    if role in {"admin", "customer"}:
        add_finding(
            "sql-injection-login-bypass",
            "Authentication bypass via SQL injection",
            "critical",
            f"The login endpoint returned an authenticated role ({role}) for a SQL-injection test payload (HTTP {status}).",
            "Authentication Bypass via SQL Injection in Login API",
        )
        add_check("sql-injection-login", "finding", "Authenticated response observed")
    else:
        add_check(
            "sql-injection-login",
            "passed",
            f"The injection payload was not accepted as an authenticated role (HTTP {status}).",
        )


def check_transport_and_cookie_flags() -> None:
    parsed = urlparse(BASE_URL)
    if parsed.scheme != "https":
        add_finding(
            "cleartext-http-transport",
            "Sensitive traffic is served over HTTP",
            "high",
            "The configured security target uses HTTP, so credentials and session cookies are not protected by TLS.",
            "Cleartext Exposure of Login Credentials and Session Cookies over HTTP",
        )
        add_check("https-transport", "finding", "Target URL is HTTP")
    else:
        add_check("https-transport", "passed", "Target URL uses HTTPS")

    status, headers, _ = request("GET", "/Admin/login.php")
    cookies = set_cookie_headers(headers)
    if not cookies:
        add_check(
            "session-cookie-flags",
            "inconclusive",
            f"Login page returned HTTP {status} without a Set-Cookie header.",
        )
        return

    cookie_text = " ".join(cookies).lower()
    if "httponly" not in cookie_text:
        add_finding(
            "session-cookie-httponly",
            "Session cookie lacks HttpOnly",
            "medium",
            "The PHP session cookie was issued without the HttpOnly attribute.",
            "Admin Session Reuse through Exposed PHPSESSID",
        )
    if "secure" not in cookie_text:
        add_finding(
            "session-cookie-secure",
            "Session cookie lacks Secure",
            "high",
            "The PHP session cookie was issued without the Secure attribute.",
            "Cleartext Exposure of Login Credentials and Session Cookies over HTTP",
        )
    if "samesite=" not in cookie_text:
        add_finding(
            "session-cookie-samesite",
            "Session cookie lacks SameSite",
            "medium",
            "The PHP session cookie was issued without a SameSite attribute.",
            "Admin Session Reuse through Exposed PHPSESSID",
        )
    add_check("session-cookie-flags", "completed", f"Inspected {len(cookies)} Set-Cookie header(s)")


def check_unauthenticated_admin_access() -> None:
    status, headers, body = request(
        "GET", "/Admin/index.php", cookie="PHPSESSID=manual-invalid-session"
    )
    if admin_page_is_accessible(status, headers, body):
        add_finding(
            "admin-access-with-invalid-session",
            "Admin page accepts an invalid session",
            "high",
            "The admin page was accessible with a deliberately invalid PHPSESSID.",
            "Admin Session Reuse through Exposed PHPSESSID",
        )
        add_check("invalid-session-admin-access", "finding", "Admin content was accessible")
    else:
        add_check("invalid-session-admin-access", "passed", "Invalid session was rejected")


def check_optional_session_replay() -> None:
    email = os.environ.get("SECURITY_TEST_ADMIN_EMAIL", "")
    password = os.environ.get("SECURITY_TEST_ADMIN_PASSWORD", "")
    if not email or not password:
        add_check(
            "logout-session-replay",
            "skipped",
            "Set SECURITY_TEST_ADMIN_EMAIL and SECURITY_TEST_ADMIN_PASSWORD to run the disposable-admin session replay check.",
        )
        return

    status, headers, body = request(
        "POST",
        "/server/api.php?function_code=login",
        {"email": email, "password": password},
    )
    role = body.strip().lower()
    cookie = session_cookie(headers)
    if role != "admin" or cookie is None:
        add_check(
            "logout-session-replay",
            "inconclusive",
            f"Disposable admin login did not return an admin session (HTTP {status}).",
        )
        return

    cookie_header = f"{cookie[0]}={cookie[1]}"
    request("GET", "/Admin/index.php", cookie=cookie_header)
    request("GET", "/Admin/logout.php", cookie=cookie_header)
    replay_status, replay_headers, replay_body = request(
        "GET", "/Admin/index.php", cookie=cookie_header
    )
    if admin_page_is_accessible(replay_status, replay_headers, replay_body):
        add_finding(
            "session-reuse-after-logout",
            "Session remains valid after logout",
            "high",
            "A copied disposable admin session continued to access the admin page after logout.",
            "Admin Session Reuse through Exposed PHPSESSID",
        )
        add_check("logout-session-replay", "finding", "Session remained usable")
    else:
        add_check("logout-session-replay", "passed", "Session was invalidated after logout")


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        check_target()
        check_sql_injection()
        check_transport_and_cookie_flags()
        check_unauthenticated_admin_access()
        check_optional_session_replay()
    except Exception as exc:  # Keep a machine-readable report for infrastructure failures.
        errors.append({"type": type(exc).__name__, "message": str(exc)})

    report = {
        "target": BASE_URL,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "findings": findings,
        "errors": errors,
        "manual_follow_up": [
            "Use Burp Suite or curl to replay the login SQL-injection regression request.",
            "Use browser DevTools or Burp Repeater to copy a disposable admin PHPSESSID, then verify access is denied after logout.",
            "Use Wireshark on the local test interface to confirm credentials and cookies are not visible in cleartext after HTTPS is enabled.",
        ],
    }
    (REPORT_DIR / "manual-security-regression.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )

    print(json.dumps({"checks": len(checks), "findings": len(findings), "errors": len(errors)}))
    if errors:
        return 2
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
