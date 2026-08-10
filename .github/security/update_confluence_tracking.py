#!/usr/bin/env python3
"""Update the three-row Confluence vulnerability tracking table.

The page is read and rewritten through Confluence's storage-format API. Only
the Mode, Status, and Update timestamp cells in the three named vulnerability
rows are changed; the rest of the page is preserved.

Status is intentionally conservative: FIXED is written only when the
corresponding regression checks provide evidence that the issue is no longer
present. A missing, skipped, inconclusive, or infrastructure-failed check is
reported as VULNERABLE rather than silently claiming a fix.
"""

from __future__ import annotations

import base64
import html
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo


BASE_URL = os.environ.get("CONFLUENCE_BASE_URL", "https://lukaazhun.atlassian.net").rstrip("/")
PAGE_ID = os.environ.get("CONFLUENCE_PAGE_ID", "65975")
EMAIL = os.environ.get("CONFLUENCE_EMAIL", "")
TOKEN = os.environ.get("CONFLUENCE_API_TOKEN", "")
MODE = os.environ.get("CONFLUENCE_MODE", "SCAN").strip().upper() or "SCAN"
REPORT_PATH = Path(
    os.environ.get("CONFLUENCE_SECURITY_REPORT", "security-reports/manual-security-regression.json")
)

ROW_LABELS = {
    "sql injection": "SQL injection",
    "weak session management": "Weak session management",
    "insecure http": "Insecure HTTP",
}

ROW_RE = re.compile(r"<tr\b[^>]*>.*?</tr>", re.IGNORECASE | re.DOTALL)
CELL_RE = re.compile(r"<t[dh]\b[^>]*>.*?</t[dh]>", re.IGNORECASE | re.DOTALL)
CELL_CONTENT_RE = re.compile(
    r"(?P<opening><t[dh]\b[^>]*>).*?(?P<closing></t[dh]>)$",
    re.IGNORECASE | re.DOTALL,
)


def normalise_text(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value)
    return " ".join(html.unescape(without_tags).split()).casefold()


def replace_cell(cell: str, value: str) -> str:
    match = CELL_CONTENT_RE.fullmatch(cell)
    if match is None:
        raise ValueError("could not parse a Confluence table cell")
    return f"{match.group('opening')}{html.escape(value)}{match.group('closing')}"


def update_tracking_table(body: str, statuses: Dict[str, str], mode: str, timestamp: str) -> str:
    """Return storage HTML with the three tracking rows updated."""

    found: Dict[str, int] = {key: 0 for key in ROW_LABELS}

    def update_row(row_match: re.Match[str]) -> str:
        row = row_match.group(0)
        cells = list(CELL_RE.finditer(row))
        if not cells:
            return row

        label = normalise_text(cells[0].group(0))
        if label not in ROW_LABELS:
            return row

        found[label] += 1
        if found[label] > 1:
            raise ValueError(f"Confluence page contains duplicate row: {ROW_LABELS[label]}")
        if len(cells) < 4:
            raise ValueError(
                f"Confluence tracking row has fewer than four cells: {ROW_LABELS[label]}"
            )

        replacements = {
            1: mode,
            2: statuses[label],
            3: timestamp,
        }
        pieces: List[str] = []
        cursor = 0
        for index, cell_match in enumerate(cells):
            pieces.append(row[cursor : cell_match.start()])
            pieces.append(
                replace_cell(cell_match.group(0), replacements[index])
                if index in replacements
                else cell_match.group(0)
            )
            cursor = cell_match.end()
        pieces.append(row[cursor:])
        return "".join(pieces)

    updated = ROW_RE.sub(update_row, body)
    missing = [ROW_LABELS[key] for key, count in found.items() if count == 0]
    if missing:
        raise ValueError("Confluence tracking rows not found: " + ", ".join(missing))
    return updated


def auth_header() -> str:
    encoded = base64.b64encode(f"{EMAIL}:{TOKEN}".encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def confluence_request(method: str, url: str, payload: object = None) -> dict:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Authorization": auth_header(),
    }
    if data is not None:
        headers["Content-Type"] = "application/json"

    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise RuntimeError(f"Confluence API returned HTTP {error.code} for {method} {url}") from error
    except URLError as error:
        raise RuntimeError(f"Confluence API request failed: {error.reason}") from error


def load_report() -> dict:
    if not REPORT_PATH.is_file():
        raise RuntimeError(f"security report was not found: {REPORT_PATH}")
    try:
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"could not read security report {REPORT_PATH}: {error}") from error
    if not isinstance(report, dict):
        raise RuntimeError("security report must contain a JSON object")
    return report


def report_statuses(report: dict) -> Tuple[Dict[str, str], Dict[str, str]]:
    findings = report.get("findings") or []
    finding_ids = {
        str(item.get("id"))
        for item in findings
        if isinstance(item, dict) and item.get("id")
    }
    checks = report.get("checks") or []
    check_statuses = {
        str(item.get("name")): str(item.get("status"))
        for item in checks
        if isinstance(item, dict) and item.get("name")
    }
    has_errors = bool(report.get("errors"))

    reasons: Dict[str, str] = {}
    statuses: Dict[str, str] = {}

    if has_errors:
        for key, label in ROW_LABELS.items():
            statuses[key] = "VULNERABLE"
            reasons[key] = "the security regression report contains an infrastructure error"
        return statuses, reasons

    if "sql-injection-login-bypass" in finding_ids:
        statuses["sql injection"] = "VULNERABLE"
        reasons["sql injection"] = "the SQL injection login check produced a finding"
    elif check_statuses.get("sql-injection-login") == "passed":
        statuses["sql injection"] = "FIXED"
        reasons["sql injection"] = "the SQL injection login check passed"
    else:
        statuses["sql injection"] = "VULNERABLE"
        reasons["sql injection"] = "the SQL injection check did not provide a passing result"

    session_finding_ids = {
        "session-cookie-httponly",
        "session-cookie-samesite",
        "session-reuse-after-logout",
        "admin-access-with-invalid-session",
    }
    if finding_ids.intersection(session_finding_ids):
        statuses["weak session management"] = "VULNERABLE"
        reasons["weak session management"] = "the session-management checks produced a finding"
    elif (
        check_statuses.get("session-cookie-flags") == "completed"
        and check_statuses.get("invalid-session-admin-access") == "passed"
        and check_statuses.get("logout-session-replay") == "passed"
    ):
        statuses["weak session management"] = "FIXED"
        reasons["weak session management"] = "cookie, invalid-session, and logout replay checks passed"
    else:
        statuses["weak session management"] = "VULNERABLE"
        reasons["weak session management"] = "one or more session checks were skipped or inconclusive"

    transport_finding_ids = {"cleartext-http-transport", "session-cookie-secure"}
    if finding_ids.intersection(transport_finding_ids):
        statuses["insecure http"] = "VULNERABLE"
        reasons["insecure http"] = "the transport or Secure-cookie check produced a finding"
    elif check_statuses.get("https-transport") == "passed":
        statuses["insecure http"] = "FIXED"
        reasons["insecure http"] = "the HTTPS transport check passed"
    else:
        statuses["insecure http"] = "VULNERABLE"
        reasons["insecure http"] = "the HTTPS transport check did not pass"

    return statuses, reasons


def main() -> int:
    if not EMAIL or not TOKEN:
        raise RuntimeError("CONFLUENCE_EMAIL and CONFLUENCE_API_TOKEN are required")
    if MODE not in {"SCAN", "FIX"}:
        raise RuntimeError("CONFLUENCE_MODE must be SCAN or FIX")

    report = load_report()
    statuses, reasons = report_statuses(report)
    timestamp = datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).strftime("%Y-%m-%d %H:%M:%S MYT")

    page_url = f"{BASE_URL}/wiki/rest/api/content/{PAGE_ID}?expand=body.storage,version"
    page = confluence_request("GET", page_url)
    body = page.get("body", {}).get("storage", {}).get("value")
    version = page.get("version", {}).get("number")
    title = page.get("title")
    if not isinstance(body, str) or not isinstance(version, int) or not isinstance(title, str):
        raise RuntimeError("Confluence response did not contain the expected page body, title, and version")

    updated_body = update_tracking_table(body, statuses, MODE, timestamp)
    payload = {
        "version": {"number": version + 1},
        "title": title,
        "type": "page",
        "body": {"storage": {"value": updated_body, "representation": "storage"}},
    }
    updated_page = confluence_request("PUT", page_url.split("?", 1)[0], payload)
    updated_version = updated_page.get("version", {}).get("number", version + 1)

    print(f"Confluence vulnerability tracking updated: page={PAGE_ID} version={updated_version} mode={MODE}")
    for key, label in ROW_LABELS.items():
        print(f"{label}: {MODE} / {statuses[key]} ({reasons[key]}) at {timestamp}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"::error::{error}", file=sys.stderr)
        sys.exit(1)
