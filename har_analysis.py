"""Parse and analyze Burp/browser HAR exports for web security testing."""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlparse

MAX_HAR_BYTES = 50 * 1024 * 1024
INTERESTING_PATH_RE = re.compile(
    r"(admin|api|login|auth|token|password|upload|graphql|swagger|internal|debug|config)",
    re.I,
)
SENSITIVE_HEADER_NAMES = frozenset(
    name.lower()
    for name in (
        "Authorization",
        "Cookie",
        "X-Api-Key",
        "X-Auth-Token",
        "Proxy-Authorization",
    )
)


class HarAnalysisError(ValueError):
    pass


def validate_har_file(file_path: str) -> str:
    if not file_path or not file_path.strip():
        raise HarAnalysisError("A HAR file path is required.")
    resolved = os.path.realpath(
        file_path.strip()
        if os.path.isabs(file_path.strip())
        else os.path.join(os.getcwd(), file_path.strip())
    )
    if not os.path.exists(resolved):
        raise HarAnalysisError(f"HAR file not found: '{file_path}'.")
    if not os.path.isfile(resolved):
        raise HarAnalysisError(f"'{file_path}' is not a regular file.")
    if os.path.getsize(resolved) > MAX_HAR_BYTES:
        raise HarAnalysisError("HAR file exceeds the 50 MB analysis limit.")
    if not resolved.lower().endswith((".har", ".json")):
        raise HarAnalysisError("HAR files must use a .har or .json extension.")
    return resolved


def _header_map(items: list[dict]) -> dict[str, str]:
    result = {}
    for item in items or []:
        name = (item.get("name") or "").strip()
        value = (item.get("value") or "").strip()
        if name:
            result[name.lower()] = value
    return result


def _query_params(query_string: list[dict]) -> list[str]:
    names = []
    for item in query_string or []:
        name = (item.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def _body_params(post_data: dict | None) -> tuple[str, list[str]]:
    if not post_data:
        return "none", []
    mime = (post_data.get("mimeType") or "").lower()
    text = post_data.get("text") or ""
    params = _query_params(post_data.get("params"))
    if params:
        body_type = "form" if "form" in mime else "multipart" if "multipart" in mime else "form"
        return body_type, params
    if "json" in mime and text.strip():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return "json", []
        if isinstance(parsed, dict):
            return "json", list(parsed.keys())
        return "json", []
    if text.strip():
        return "raw", []
    return "none", []


def _endpoint_key(method: str, url: str) -> str:
    parsed = urlparse(url)
    return f"{method.upper()} {parsed.scheme}://{parsed.netloc}{parsed.path}"


def analyze_har(file_path: str) -> dict:
    """Return structured inventory and security observations from a HAR export."""
    resolved = validate_har_file(file_path)
    try:
        with open(resolved, encoding="utf-8") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as exc:
        raise HarAnalysisError(f"Invalid JSON in HAR file: {exc}") from exc
    except OSError as exc:
        raise HarAnalysisError(f"Could not read HAR file: {exc}") from exc

    entries = (document.get("log") or {}).get("entries") or []
    if not entries:
        raise HarAnalysisError("HAR file contains no traffic entries.")

    endpoints = []
    observations = []
    methods_count: dict[str, int] = {}
    hosts: set[str] = set()
    insecure_http = 0
    seen_keys: set[str] = set()

    for entry in entries:
        request = entry.get("request") or {}
        response = entry.get("response") or {}
        method = (request.get("method") or "GET").upper()
        url = request.get("url") or ""
        if not url:
            continue

        methods_count[method] = methods_count.get(method, 0) + 1
        parsed = urlparse(url)
        hosts.add(parsed.netloc)
        if parsed.scheme == "http":
            insecure_http += 1

        req_headers = _header_map(request.get("headers"))
        query_params = _query_params(request.get("queryString"))
        body_type, body_params = _body_params(request.get("postData"))
        key = _endpoint_key(method, url)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        endpoint = {
            "method": method,
            "url": url,
            "path": parsed.path,
            "query_params": query_params,
            "body_type": body_type,
            "body_params": body_params,
            "has_auth_header": any(name in req_headers for name in SENSITIVE_HEADER_NAMES),
            "content_type": req_headers.get("content-type", ""),
            "status": response.get("status"),
        }
        endpoints.append(endpoint)

        if parsed.scheme == "http":
            observations.append(
                {
                    "type": "insecure_transport",
                    "severity": "medium",
                    "detail": f"HTTP (cleartext) request observed: {method} {url}",
                    "owasp": "A02:2021 Cryptographic Failures",
                }
            )
        if INTERESTING_PATH_RE.search(parsed.path):
            observations.append(
                {
                    "type": "interesting_path",
                    "severity": "informational",
                    "detail": f"Sensitive-looking path: {method} {parsed.path}",
                    "owasp": "A05:2021 Security Misconfiguration",
                }
            )
        if method in {"POST", "PUT", "PATCH"} and body_params:
            observations.append(
                {
                    "type": "injectable_body",
                    "severity": "informational",
                    "detail": (
                        f"{method} {parsed.path} accepts {body_type} parameters: "
                        f"{', '.join(body_params[:8])}"
                    ),
                    "owasp": "A03:2021 Injection",
                }
            )
        if query_params:
            observations.append(
                {
                    "type": "injectable_query",
                    "severity": "informational",
                    "detail": f"{method} {parsed.path} query params: {', '.join(query_params[:8])}",
                    "owasp": "A03:2021 Injection",
                }
            )

    recommended_probes = []
    for endpoint in endpoints[:25]:
        url = endpoint["url"]
        for param in endpoint["query_params"][:3]:
            recommended_probes.append(
                {"check_type": "sql_error_probe", "url": url, "parameter": param, "source": "har_query"}
            )
        if endpoint["body_type"] == "form":
            check = "post_form_sql_error"
            for param in endpoint["body_params"][:3]:
                recommended_probes.append(
                    {"check_type": check, "url": url, "parameter": param, "source": "har_form_body"}
                )
        elif endpoint["body_type"] == "json":
            check = "post_json_sql_error"
            for param in endpoint["body_params"][:3]:
                recommended_probes.append(
                    {"check_type": check, "url": url, "parameter": param, "source": "har_json_body"}
                )

    return {
        "file": resolved,
        "summary": {
            "total_entries": len(entries),
            "unique_endpoints": len(endpoints),
            "methods": methods_count,
            "unique_hosts": sorted(hosts),
            "insecure_http_count": insecure_http,
        },
        "endpoints": endpoints[:100],
        "security_observations": observations[:80],
        "recommended_probes": recommended_probes[:40],
        "burp_next_steps": [
            "Re-run high-value POST/JSON endpoints in Burp Repeater with session cookies from the HAR.",
            "Use Intruder on parameters listed under recommended_probes.",
            "Compare authenticated vs unauthenticated responses for access-control issues.",
        ],
    }
