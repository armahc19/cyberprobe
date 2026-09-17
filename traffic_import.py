"""Unified Burp HAR/XML traffic import and analysis."""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlparse

from har_analysis import HarAnalysisError, analyze_har

MAX_TRAFFIC_BYTES = 50 * 1024 * 1024
INTERESTING_PATH_RE = re.compile(
    r"(admin|api|login|auth|token|password|upload|graphql|swagger|internal|debug|config)",
    re.I,
)
SENSITIVE_HEADER_NAMES = frozenset(
    name.lower()
    for name in ("authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization")
)


class TrafficImportError(ValueError):
    pass


def validate_traffic_file(file_path: str) -> tuple[str, str]:
    if not file_path or not file_path.strip():
        raise TrafficImportError("A traffic export file path is required.")
    resolved = os.path.realpath(
        file_path.strip()
        if os.path.isabs(file_path.strip())
        else os.path.join(os.getcwd(), file_path.strip())
    )
    if not os.path.exists(resolved):
        raise TrafficImportError(f"Traffic file not found: '{file_path}'.")
    if not os.path.isfile(resolved):
        raise TrafficImportError(f"'{file_path}' is not a regular file.")
    if os.path.getsize(resolved) > MAX_TRAFFIC_BYTES:
        raise TrafficImportError("Traffic file exceeds the 50 MB analysis limit.")
    lowered = resolved.lower()
    if lowered.endswith((".har", ".json")):
        return resolved, "har"
    if lowered.endswith(".xml"):
        return resolved, "xml"
    raise TrafficImportError("Traffic files must use .har, .json, or .xml (Burp export).")


def _parse_request_line(request_text: str) -> tuple[str, str, dict[str, str]]:
    lines = request_text.replace("\r\n", "\n").split("\n")
    if not lines:
        return "GET", "/", {}
    parts = lines[0].split()
    method = parts[0].upper() if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return method, path, headers


def _body_params_from_request(headers: dict[str, str], body: str) -> tuple[str, list[str]]:
    content_type = headers.get("content-type", "").lower()
    if not body.strip():
        return "none", []
    if "json" in content_type:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            return "json", []
        if isinstance(parsed, dict):
            return "json", list(parsed.keys())
        return "json", []
    if "form" in content_type:
        params = []
        for pair in body.split("&"):
            if "=" in pair:
                name = pair.split("=", 1)[0]
                if name and name not in params:
                    params.append(name)
        return "form", params
    return "raw", []


def analyze_burp_xml(file_path: str) -> dict:
    resolved, _ = validate_traffic_file(file_path)
    try:
        tree = ET.parse(resolved)
    except ET.ParseError as exc:
        raise TrafficImportError(f"Invalid Burp XML: {exc}") from exc

    root = tree.getroot()
    items = root.findall("item")
    if not items:
        raise TrafficImportError("Burp XML contains no item entries.")

    endpoints = []
    observations = []
    methods_count: dict[str, int] = {}
    hosts: set[str] = set()
    insecure_http = 0
    seen_keys: set[str] = set()

    for item in items:
        url = (item.findtext("url") or "").strip()
        if not url:
            host = (item.findtext("host") or "").strip()
            protocol = (item.findtext("protocol") or "https").strip()
            port = (item.findtext("port") or ("443" if protocol == "https" else "80")).strip()
            path = (item.findtext("path") or "/").strip()
            default_port = "443" if protocol == "https" else "80"
            if port and port != default_port:
                url = f"{protocol}://{host}:{port}{path}"
            else:
                url = f"{protocol}://{host}{path}"

        method = (item.findtext("method") or "GET").strip().upper()
        request_text = item.findtext("request") or ""
        method_line, req_path, req_headers = _parse_request_line(request_text)
        if method_line:
            method = method_line

        parsed = urlparse(url)
        hosts.add(parsed.netloc)
        methods_count[method] = methods_count.get(method, 0) + 1
        if parsed.scheme == "http":
            insecure_http += 1

        query_params = list(parse_qs(parsed.query).keys())
        body = ""
        if "\n\n" in request_text.replace("\r\n", "\n"):
            body = request_text.replace("\r\n", "\n").split("\n\n", 1)[1]
        body_type, body_params = _body_params_from_request(req_headers, body)

        status_text = item.findtext("status") or item.findtext("response/@status")
        status = int(status_text) if status_text and status_text.isdigit() else None

        key = f"{method} {parsed.scheme}://{parsed.netloc}{parsed.path}"
        if key in seen_keys:
            continue
        seen_keys.add(key)

        endpoint = {
            "method": method,
            "url": url,
            "path": parsed.path or req_path,
            "query_params": query_params,
            "body_type": body_type,
            "body_params": body_params,
            "has_auth_header": any(name in req_headers for name in SENSITIVE_HEADER_NAMES),
            "content_type": req_headers.get("content-type", ""),
            "status": status,
        }
        endpoints.append(endpoint)

        if parsed.scheme == "http":
            observations.append(
                {
                    "type": "insecure_transport",
                    "severity": "medium",
                    "detail": f"HTTP request observed: {method} {url}",
                    "owasp": "A02:2021 Cryptographic Failures",
                }
            )
        if INTERESTING_PATH_RE.search(parsed.path or ""):
            observations.append(
                {
                    "type": "interesting_path",
                    "severity": "informational",
                    "detail": f"Sensitive-looking path: {method} {parsed.path}",
                    "owasp": "A05:2021 Security Misconfiguration",
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
        if body_params:
            observations.append(
                {
                    "type": "injectable_body",
                    "severity": "informational",
                    "detail": f"{method} {parsed.path} {body_type} params: {', '.join(body_params[:8])}",
                    "owasp": "A03:2021 Injection",
                }
            )

    recommended_probes = _build_recommended_probes(endpoints)

    return {
        "file": resolved,
        "format": "burp_xml",
        "summary": {
            "total_entries": len(items),
            "unique_endpoints": len(endpoints),
            "methods": methods_count,
            "unique_hosts": sorted(hosts),
            "insecure_http_count": insecure_http,
        },
        "endpoints": endpoints[:100],
        "security_observations": observations[:80],
        "recommended_probes": recommended_probes[:40],
        "burp_next_steps": [
            "Re-run high-value endpoints in Burp Repeater with session cookies from the export.",
            "Use Intruder on parameters listed under recommended_probes.",
            "Run idor_dual_session_check with two test-account cookies.",
        ],
    }


def _build_recommended_probes(endpoints: list[dict]) -> list[dict]:
    recommended = []
    for endpoint in endpoints[:25]:
        url = endpoint["url"]
        for param in endpoint["query_params"][:3]:
            recommended.append(
                {"check_type": "sql_error_probe", "url": url, "parameter": param, "source": "traffic_query"}
            )
        if endpoint["body_type"] == "form":
            for param in endpoint["body_params"][:3]:
                recommended.append(
                    {"check_type": "post_form_sql_error", "url": url, "parameter": param, "source": "traffic_form"}
                )
        elif endpoint["body_type"] == "json":
            for param in endpoint["body_params"][:3]:
                recommended.append(
                    {"check_type": "post_json_sql_error", "url": url, "parameter": param, "source": "traffic_json"}
                )
        if endpoint.get("has_auth_header"):
            recommended.append(
                {
                    "check_type": "idor_dual_session_check",
                    "url": url,
                    "parameter": endpoint["query_params"][0] if endpoint["query_params"] else "id",
                    "source": "authenticated_endpoint",
                }
            )
    return recommended


def analyze_traffic_file(file_path: str) -> dict:
    """Analyze a Burp HAR or Burp XML export."""
    _, fmt = validate_traffic_file(file_path)
    if fmt == "har":
        report = analyze_har(file_path)
        report["format"] = "har"
        return report
    return analyze_burp_xml(file_path)
