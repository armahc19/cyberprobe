"""Web application security checks: recon, passive analysis, and safe input probes."""

from __future__ import annotations

import json
import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from har_analysis import HarAnalysisError, analyze_har
from traffic_import import TrafficImportError, analyze_traffic_file

PROJECT_ROOT = Path(__file__).resolve().parent
WORDLISTS = {
    "common_dirs": PROJECT_ROOT / "wordlists" / "common_dirs.txt",
    "api_paths": PROJECT_ROOT / "wordlists" / "api_paths.txt",
}

SYSTEM_WORDLIST_FALLBACKS = {
    "common_dirs": Path("/usr/share/wordlists/dirb/common.txt"),
    "api_paths": Path("/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
}

PARAM_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,64}$")
SQL_PROBE_PAYLOADS = ("'", '"', "1'", '1"', "''")
XSS_PROBE_PAYLOADS = (
    "cyberprobe_xss_canary_7x9",
    "<cyberprobe>",
    "\"><cyberprobe>",
)
SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "sqlite",
    "postgresql",
    "ora-",
    "odbc",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
)

MAX_OUTPUT = 12000
HTTP_TIMEOUT = 15
BRUTEFORCE_TIMEOUT = 90
DEFAULT_BURP_PROXY = "http://127.0.0.1:8080"

LAB_EXPLOIT_TYPES = {
    "sql_union_probe": {
        "payload": "' UNION SELECT NULL--",
        "owasp": "A03:2021 Injection",
    },
    "xss_script_probe": {
        "payload": "<script>cyberprobe_lab_poc</script>",
        "owasp": "A03:2021 Injection",
    },
    "path_traversal_probe": {
        "payload": "../../../etc/passwd",
        "owasp": "A01:2021 Broken Access Control",
    },
}
TRAVERSAL_MARKERS = ("root:x:", "bin/bash", "daemon:")

URL_OPTIONAL_CHECKS = frozenset({
    "analyze_har_file", "har_automated_probes", "analyze_traffic_file", "analyze_burp_xml_file",
})

_ACTIVE_CTX: "CheckContext | None" = None


@dataclass
class CheckContext:
    url: str = ""
    parameter: str | None = None
    wordlist: str | None = None
    file_path: str | None = None
    use_burp_proxy: bool = False
    burp_proxy_url: str = DEFAULT_BURP_PROXY
    session_cookie_a: str | None = None
    session_cookie_b: str | None = None
    resource_id_a: str | None = None
    resource_id_b: str | None = None
    exploit_type: str | None = None
    confirm_lab_exploit: bool = False

ALLOWED_CHECKS = {
    # --- Passive / configuration ---
    "http_headers": "Inspect HTTP response headers for security configuration.",
    "http_methods": "Inspect advertised HTTP methods via OPTIONS.",
    "fetch_resource": "Fetch a web resource and return status, headers, and body preview.",
    "cookie_analysis": "Inspect Set-Cookie flags (Secure, HttpOnly, SameSite).",
    "cors_probe": "Send an Origin header and inspect Access-Control-Allow-Origin behavior.",
    "redirect_chain": "Follow redirects and report each hop.",
    "robots_txt": "Fetch /robots.txt for exposed paths.",
    "security_txt": "Fetch /.well-known/security.txt for disclosure contacts.",
    "tls_certificate": "Inspect the TLS certificate subject and expiry.",
    "technology_fingerprint": "Identify web technologies with whatweb.",
    # --- Recon / mapping ---
    "subdomain_enum": "Enumerate subdomains with subfinder (passive DNS sources).",
    "directory_bruteforce": "Discover hidden directories with gobuster.",
    "api_discovery": "Probe common API and documentation paths with ffuf.",
    "common_path_probe": "Request a fixed list of sensitive paths without brute force.",
    # --- Input manipulation: GET query params ---
    "parameter_reflection": "Inject a canary into a GET query parameter and detect reflection.",
    "sql_error_probe": "Send safe SQL metacharacters in a GET query param; detect error leakage.",
    "xss_reflection_probe": "Send HTML canary strings in a GET query param; detect reflection.",
    # --- Input manipulation: POST form bodies ---
    "post_form_reflection": "Inject a canary into an application/x-www-form-urlencoded POST field.",
    "post_form_sql_error": "Send SQL metacharacters in a POST form field; detect error leakage.",
    "post_form_xss_reflection": "Send HTML canaries in a POST form field; detect reflection.",
    # --- Input manipulation: POST JSON bodies ---
    "post_json_reflection": "Inject a canary into a JSON POST body field.",
    "post_json_sql_error": "Send SQL metacharacters in a JSON POST field; detect error leakage.",
    "post_json_xss_reflection": "Send HTML canaries in a JSON POST field; detect reflection.",
    # --- Burp / traffic import ---
    "analyze_har_file": "Parse a Burp/browser HAR export and inventory injectable endpoints.",
    "analyze_burp_xml_file": "Parse a Burp Suite XML export and inventory injectable endpoints.",
    "analyze_traffic_file": "Auto-detect and analyze a Burp HAR or XML export.",
    "har_automated_probes": "Run safe input probes on endpoints discovered in a traffic export.",
    # --- Access control ---
    "idor_dual_session_check": "Compare two session cookies for horizontal IDOR (A01/A07).",
    # --- Deeper hunting ---
    "nuclei_web_scan": "Run nuclei web templates (cve, misconfig, exposure, tech).",
    # --- Burp proxy ---
    "burp_proxy_ping": "Verify Burp proxy listener is reachable (default 127.0.0.1:8080).",
    # --- Gated lab exploitation (PoC only) ---
    "lab_exploit_poc": "Authorized lab PoC: sql_union_probe, xss_script_probe, or path_traversal_probe.",
}


class WebTargetError(ValueError):
    pass


def _resolve_wordlist(name: str | None) -> Path:
    choice = (name or "common_dirs").strip()
    if choice not in WORDLISTS:
        raise WebTargetError(f"Wordlist must be one of: {', '.join(WORDLISTS)}.")
    bundled = WORDLISTS[choice]
    if bundled.exists():
        return bundled
    fallback = SYSTEM_WORDLIST_FALLBACKS.get(choice)
    if fallback and fallback.exists():
        return fallback
    raise WebTargetError(f"No wordlist file found for '{choice}'.")


def validate_url(value: str) -> str:
    value = (value or "").strip()
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise WebTargetError("Use a complete http:// or https:// URL.")
    if any(ch in value for ch in [";", "|", "&", "`", "\n", "\r"]):
        raise WebTargetError("The URL contains unsupported characters.")
    return value


def url_hostname(value: str) -> str:
    return urllib.parse.urlparse(validate_url(value)).hostname.lower()


def validate_parameter(value: str | None) -> str:
    param = (value or "q").strip()
    if not PARAM_RE.fullmatch(param):
        raise WebTargetError("Parameter names may only contain letters, numbers, underscores, and hyphens.")
    return param


def _proxy_settings() -> tuple[bool, str]:
    ctx = _ACTIVE_CTX or CheckContext()
    return ctx.use_burp_proxy, ctx.burp_proxy_url or DEFAULT_BURP_PROXY


def _curl_proxy_args() -> list[str]:
    use_proxy, proxy_url = _proxy_settings()
    if not use_proxy:
        return []
    return ["--proxy", proxy_url, "-k"]


def _build_opener(use_proxy: bool, proxy_url: str):
    if not use_proxy:
        return urllib.request.build_opener()
    proxy_handler = urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
    return urllib.request.build_opener(proxy_handler, https_handler)


def _http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    body: str | bytes | dict | None = None,
    content_type: str | None = None,
    timeout: int = HTTP_TIMEOUT,
) -> dict:
    use_proxy, proxy_url = _proxy_settings()
    req_headers = dict(headers or {})
    payload: bytes | None = None
    if body is not None:
        if isinstance(body, dict):
            payload = json.dumps(body).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, bytes):
            payload = body
        else:
            payload = str(body).encode("utf-8")
        if content_type:
            req_headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=payload, method=method, headers=req_headers)
    opener = _build_opener(use_proxy, proxy_url)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(8000).decode("utf-8", errors="replace")
            return {
                "url": url,
                "method": method,
                "status": response.status,
                "headers": dict(response.headers.items()),
                "body_preview": raw[:4000],
                "via_burp_proxy": use_proxy,
            }
    except urllib.error.HTTPError as exc:
        raw = exc.read(8000).decode("utf-8", errors="replace")
        return {
            "url": url,
            "method": method,
            "status": exc.code,
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body_preview": raw[:4000],
            "via_burp_proxy": use_proxy,
        }
    except urllib.error.URLError as exc:
        return {
            "url": url,
            "method": method,
            "error": str(exc.reason),
            "status": None,
            "headers": {},
            "body_preview": "",
            "via_burp_proxy": use_proxy,
        }


def _inject_query_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(validate_url(url))
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _run_subprocess(command: list[str], timeout: int) -> dict:
    if shutil.which(command[0]) is None:
        return {
            "command": " ".join(command),
            "returncode": 127,
            "stdout": "",
            "stderr": f"Required tool not installed: {command[0]}",
            "timed_out": False,
        }
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return {
            "command": " ".join(command),
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[:MAX_OUTPUT],
            "stderr": (proc.stderr or "")[:3000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": " ".join(command),
            "returncode": -1,
            "stdout": exc.stdout or "",
            "stderr": exc.stderr or "",
            "timed_out": True,
        }


def _check_http_headers(url: str) -> dict:
    result = _run_subprocess(
        ["curl", "-sS", "-D", "-", "-o", "/dev/null", "--max-time", str(HTTP_TIMEOUT)]
        + _curl_proxy_args()
        + [url],
        HTTP_TIMEOUT + 5,
    )
    result["check_type"] = "http_headers"
    result["target"] = url
    return result


def _check_http_methods(url: str) -> dict:
    result = _run_subprocess(
        ["curl", "-sS", "-i", "-X", "OPTIONS", "--max-time", str(HTTP_TIMEOUT)]
        + _curl_proxy_args()
        + [url],
        HTTP_TIMEOUT + 5,
    )
    result["check_type"] = "http_methods"
    result["target"] = url
    return result


def _check_fetch_resource(url: str) -> dict:
    probe = _http_request(url)
    return {
        "check_type": "fetch_resource",
        "target": url,
        "command": f"GET {url}",
        "returncode": 0 if probe.get("status") else 1,
        "stdout": json.dumps(probe, indent=2)[:MAX_OUTPUT],
        "stderr": probe.get("error", ""),
        "timed_out": False,
    }


def _check_cookie_analysis(url: str) -> dict:
    probe = _http_request(url)
    cookies = []
    for key, value in probe.get("headers", {}).items():
        if key.lower() == "set-cookie":
            cookies.append(value)
    analysis = []
    for cookie in cookies:
        lowered = cookie.lower()
        analysis.append(
            {
                "cookie": cookie[:500],
                "secure": "secure" in lowered,
                "httponly": "httponly" in lowered,
                "samesite": "samesite=" in lowered,
            }
        )
    payload = {"cookies": analysis, "http_status": probe.get("status")}
    return {
        "check_type": "cookie_analysis",
        "target": url,
        "command": f"GET {url}",
        "returncode": 0,
        "stdout": json.dumps(payload, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_cors_probe(url: str) -> dict:
    origin = "https://cyberprobe-origin.example"
    probe = _http_request(url, headers={"Origin": origin})
    allow_origin = probe.get("headers", {}).get("Access-Control-Allow-Origin", "")
    allow_credentials = probe.get("headers", {}).get("Access-Control-Allow-Credentials", "")
    payload = {
        "test_origin": origin,
        "access_control_allow_origin": allow_origin,
        "access_control_allow_credentials": allow_credentials,
        "http_status": probe.get("status"),
        "notes": [],
    }
    if allow_origin == "*":
        payload["notes"].append("Wildcard ACAO allows any origin.")
    elif allow_origin == origin:
        payload["notes"].append("Server reflects the supplied Origin header.")
    return {
        "check_type": "cors_probe",
        "target": url,
        "command": f"GET {url} Origin:{origin}",
        "returncode": 0,
        "stdout": json.dumps(payload, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_redirect_chain(url: str) -> dict:
    result = _run_subprocess(
        ["curl", "-sS", "-L", "-o", "/dev/null", "-w", "%{url_effective}\\n%{http_code}\\n", "--max-time", str(HTTP_TIMEOUT)]
        + _curl_proxy_args()
        + [url],
        HTTP_TIMEOUT + 5,
    )
    result["check_type"] = "redirect_chain"
    result["target"] = url
    return result


def _check_well_known(url: str, path: str, check_type: str) -> dict:
    parsed = urllib.parse.urlparse(validate_url(url))
    target = urllib.parse.urlunparse(parsed._replace(path=path, query="", fragment=""))
    probe = _http_request(target)
    return {
        "check_type": check_type,
        "target": target,
        "command": f"GET {target}",
        "returncode": 0 if probe.get("status") else 1,
        "stdout": json.dumps(probe, indent=2)[:MAX_OUTPUT],
        "stderr": probe.get("error", ""),
        "timed_out": False,
    }


def _check_tls_certificate(url: str) -> dict:
    parsed = urllib.parse.urlparse(validate_url(url))
    if parsed.scheme != "https":
        raise WebTargetError("TLS checks require an https:// URL.")
    host = parsed.hostname
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
    except OSError as exc:
        return {
            "check_type": "tls_certificate",
            "target": url,
            "command": f"TLS handshake {host}:{port}",
            "returncode": 1,
            "stdout": "",
            "stderr": str(exc),
            "timed_out": False,
        }
    payload = {
        "subject": dict(x[0] for x in cert.get("subject", ())),
        "issuer": dict(x[0] for x in cert.get("issuer", ())),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "san": cert.get("subjectAltName"),
    }
    return {
        "check_type": "tls_certificate",
        "target": url,
        "command": f"TLS handshake {host}:{port}",
        "returncode": 0,
        "stdout": json.dumps(payload, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_technology_fingerprint(url: str) -> dict:
    result = _run_subprocess(["whatweb", "-a", "1", url], HTTP_TIMEOUT + 10)
    result["check_type"] = "technology_fingerprint"
    result["target"] = url
    return result


def _check_subdomain_enum(url: str) -> dict:
    domain = url_hostname(url)
    result = _run_subprocess(["subfinder", "-d", domain, "-silent"], 120)
    result["check_type"] = "subdomain_enum"
    result["target"] = domain
    return result


def _check_directory_bruteforce(url: str, wordlist: str | None) -> dict:
    path = _resolve_wordlist(wordlist or "common_dirs")
    result = _run_subprocess(
        [
            "gobuster", "dir", "-u", validate_url(url), "-w", str(path),
            "-q", "-t", "10", "--timeout", "10s", "--no-error",
        ],
        BRUTEFORCE_TIMEOUT,
    )
    result["check_type"] = "directory_bruteforce"
    result["target"] = url
    result["wordlist"] = str(path)
    return result


def _check_api_discovery(url: str, wordlist: str | None) -> dict:
    path = _resolve_wordlist(wordlist or "api_paths")
    base = validate_url(url).rstrip("/")
    result = _run_subprocess(
        [
            "ffuf", "-u", f"{base}/FUZZ", "-w", str(path),
            "-mc", "200,301,302,401,403", "-t", "10", "-timeout", "10", "-s",
        ],
        BRUTEFORCE_TIMEOUT,
    )
    result["check_type"] = "api_discovery"
    result["target"] = url
    result["wordlist"] = str(path)
    return result


def _check_common_path_probe(url: str) -> dict:
    base = validate_url(url).rstrip("/")
    hits = []
    for entry in WORDLISTS["common_dirs"].read_text(encoding="utf-8").splitlines():
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        target = f"{base}/{entry.lstrip('/')}"
        probe = _http_request(target, timeout=8)
        status = probe.get("status")
        if status and status not in (404, 410):
            hits.append({"path": target, "status": status, "length": len(probe.get("body_preview", ""))})
    return {
        "check_type": "common_path_probe",
        "target": url,
        "command": f"GET probes against {base}",
        "returncode": 0,
        "stdout": json.dumps({"matches": hits}, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _dispatch_input_probe(
    url: str,
    parameter: str | None,
    *,
    location: str,
    mode: str,
) -> dict:
    """Run reflection, SQL error, or XSS probes against query, form, or JSON inputs."""
    param = validate_parameter(parameter)
    check_names = {
        ("query", "reflection"): "parameter_reflection",
        ("query", "sql"): "sql_error_probe",
        ("query", "xss"): "xss_reflection_probe",
        ("form", "reflection"): "post_form_reflection",
        ("form", "sql"): "post_form_sql_error",
        ("form", "xss"): "post_form_xss_reflection",
        ("json", "reflection"): "post_json_reflection",
        ("json", "sql"): "post_json_sql_error",
        ("json", "xss"): "post_json_xss_reflection",
    }
    check_type = check_names[(location, mode)]
    canary = "cyberprobe_reflection_canary_7x9"

    def send_probe(payload: str) -> tuple[dict, str]:
        if location == "query":
            target = _inject_query_param(url, param, payload)
            probe = _http_request(target)
            return probe, f"GET {target}"
        if location == "form":
            encoded = urllib.parse.urlencode({param: payload})
            probe = _http_request(
                url,
                method="POST",
                body=encoded,
                content_type="application/x-www-form-urlencoded",
            )
            return probe, f"POST {url} ({param}={payload[:40]!r})"
        encoded_json = json.dumps({param: payload})
        probe = _http_request(url, method="POST", body=encoded_json, content_type="application/json")
        return probe, f"POST {url} JSON ({param}={payload[:40]!r})"

    if mode == "reflection":
        probe, command = send_probe(canary)
        body = probe.get("body_preview", "")
        payload = {
            "location": location,
            "parameter": param,
            "canary": canary,
            "http_status": probe.get("status"),
            "reflected": canary in body,
            "note": "Reflection alone does not confirm XSS; validate encoding in Burp Repeater.",
        }
    elif mode == "sql":
        findings = []
        for payload in SQL_PROBE_PAYLOADS:
            probe, command = send_probe(payload)
            body = (probe.get("body_preview") or "").lower()
            markers = [marker for marker in SQL_ERROR_MARKERS if marker in body]
            if markers:
                findings.append(
                    {
                        "payload": payload,
                        "http_status": probe.get("status"),
                        "error_markers": markers,
                    }
                )
        payload = {"location": location, "parameter": param, "findings": findings}
        command = f"SQL error probes ({location}) on '{param}'"
    else:
        findings = []
        for payload in XSS_PROBE_PAYLOADS:
            probe, command = send_probe(payload)
            body = probe.get("body_preview", "")
            if payload in body:
                findings.append(
                    {
                        "payload": payload,
                        "http_status": probe.get("status"),
                        "reflected_unescaped": True,
                    }
                )
        payload = {"location": location, "parameter": param, "findings": findings}
        command = f"XSS reflection probes ({location}) on '{param}'"

    return {
        "check_type": check_type,
        "target": url,
        "command": command,
        "returncode": 0,
        "stdout": json.dumps(payload, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_analyze_har_file(file_path: str | None) -> dict:
    if not file_path:
        raise WebTargetError("analyze_har_file requires a file_path to a .har export.")
    try:
        report = analyze_har(file_path)
    except HarAnalysisError as exc:
        raise WebTargetError(str(exc)) from exc
    return {
        "check_type": "analyze_har_file",
        "target": report["file"],
        "command": f"analyze HAR {report['file']}",
        "returncode": 0,
        "stdout": json.dumps(report, indent=2)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def _check_analyze_traffic_file(file_path: str | None) -> dict:
    if not file_path:
        raise WebTargetError("analyze_traffic_file requires file_path to a .har or .xml export.")
    try:
        report = analyze_traffic_file(file_path)
    except (HarAnalysisError, TrafficImportError) as exc:
        raise WebTargetError(str(exc)) from exc
    return {
        "check_type": "analyze_traffic_file",
        "target": report["file"],
        "command": f"analyze traffic {report['file']} ({report.get('format', 'unknown')})",
        "returncode": 0,
        "stdout": json.dumps(report, indent=2)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def _check_analyze_burp_xml_file(file_path: str | None) -> dict:
    if not file_path:
        raise WebTargetError("analyze_burp_xml_file requires file_path to a Burp .xml export.")
    try:
        from traffic_import import analyze_burp_xml
        report = analyze_burp_xml(file_path)
    except TrafficImportError as exc:
        raise WebTargetError(str(exc)) from exc
    return {
        "check_type": "analyze_burp_xml_file",
        "target": report["file"],
        "command": f"analyze Burp XML {report['file']}",
        "returncode": 0,
        "stdout": json.dumps(report, indent=2)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def _check_idor_dual_session(ctx: CheckContext) -> dict:
    url = validate_url(ctx.url)
    param = validate_parameter(ctx.parameter or "id")
    id_a = (ctx.resource_id_a or "").strip()
    id_b = (ctx.resource_id_b or "").strip()
    cookie_a = (ctx.session_cookie_a or "").strip()
    cookie_b = (ctx.session_cookie_b or "").strip()
    if not all([id_a, id_b, cookie_a, cookie_b]):
        raise WebTargetError(
            "idor_dual_session_check requires resource_id_a, resource_id_b, "
            "session_cookie_a, and session_cookie_b."
        )

    def fetch(resource_id: str, cookie: str) -> dict:
        target = _inject_query_param(url, param, resource_id)
        return _http_request(target, headers={"Cookie": cookie})

    user_a_own = fetch(id_a, cookie_a)
    user_b_own = fetch(id_b, cookie_b)
    user_b_on_a = fetch(id_a, cookie_b)
    idor_candidate = (
        user_b_on_a.get("status") == user_a_own.get("status")
        and user_a_own.get("status") in (200, 201)
        and user_b_on_a.get("body_preview") == user_a_own.get("body_preview")
        and len(user_a_own.get("body_preview") or "") > 0
    )
    output = {
        "parameter": param,
        "resource_id_a": id_a,
        "resource_id_b": id_b,
        "user_a_own": {"status": user_a_own.get("status"), "length": len(user_a_own.get("body_preview") or "")},
        "user_b_own": {"status": user_b_own.get("status"), "length": len(user_b_own.get("body_preview") or "")},
        "user_b_accessing_a_resource": {
            "status": user_b_on_a.get("status"),
            "length": len(user_b_on_a.get("body_preview") or ""),
        },
        "idor_candidate": idor_candidate,
        "owasp": "A01:2021 Broken Access Control",
    }
    return {
        "check_type": "idor_dual_session_check",
        "target": url,
        "command": f"IDOR cross-session probe on {param}",
        "returncode": 0,
        "stdout": json.dumps(output, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_nuclei_web_scan(url: str) -> dict:
    url = validate_url(url)
    command = [
        "nuclei", "-u", url,
        "-tags", "cve,misconfig,exposure,tech,token,default-login",
        "-silent", "-timeout", "10", "-rate-limit", "20",
    ]
    use_proxy, proxy_url = _proxy_settings()
    if use_proxy:
        command.extend(["-proxy-url", proxy_url])
    result = _run_subprocess(command, 300)
    result["check_type"] = "nuclei_web_scan"
    result["target"] = url
    return result


def _check_burp_proxy_ping(ctx: CheckContext) -> dict:
    proxy = ctx.burp_proxy_url or DEFAULT_BURP_PROXY
    result = _run_subprocess(
        ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--proxy", proxy, "-k", "--max-time", "5", "http://burp/"],
        10,
    )
    reachable = result["returncode"] == 0
    return {
        "check_type": "burp_proxy_ping",
        "target": proxy,
        "command": result["command"],
        "returncode": 0 if reachable else 1,
        "stdout": json.dumps({"proxy": proxy, "reachable": reachable, "http_code": (result.get("stdout") or "").strip()}, indent=2),
        "stderr": result.get("stderr", ""),
        "timed_out": result.get("timed_out", False),
    }


def _require_lab_exploit_gate(ctx: CheckContext, url: str) -> None:
    if not ctx.confirm_lab_exploit:
        raise WebTargetError("lab_exploit_poc requires confirm_lab_exploit=true after user authorization.")
    answer = input(
        f"\n[CyberProbe] Lab exploit PoC will send proof payloads to:\n  {url}\n"
        "Authorized lab testing only. Continue? (yes/no): "
    ).strip().lower()
    if answer not in ("y", "yes"):
        raise WebTargetError("Lab exploit PoC declined by user.")


def _check_lab_exploit_poc(ctx: CheckContext) -> dict:
    url = validate_url(ctx.url)
    _require_lab_exploit_gate(ctx, url)
    exploit_type = (ctx.exploit_type or "sql_union_probe").strip()
    if exploit_type not in LAB_EXPLOIT_TYPES:
        raise WebTargetError(f"exploit_type must be one of: {', '.join(LAB_EXPLOIT_TYPES)}.")
    spec = LAB_EXPLOIT_TYPES[exploit_type]
    param = validate_parameter(ctx.parameter or "q")
    payload = spec["payload"]
    target = _inject_query_param(url, param, payload)
    probe = _http_request(target)
    body = (probe.get("body_preview") or "")
    body_lower = body.lower()
    indicators = []
    if exploit_type == "sql_union_probe" and probe.get("status") == 200 and len(body) > 50:
        indicators.append("HTTP 200 with body after UNION probe.")
    elif exploit_type == "xss_script_probe" and payload in body:
        indicators.append("Script payload reflected unescaped.")
    elif exploit_type == "path_traversal_probe":
        indicators.extend(marker for marker in TRAVERSAL_MARKERS if marker in body_lower)
    output = {
        "exploit_type": exploit_type,
        "parameter": param,
        "payload": payload,
        "http_status": probe.get("status"),
        "indicators": indicators,
        "confirmed": bool(indicators),
        "owasp": spec["owasp"],
        "via_burp_proxy": probe.get("via_burp_proxy", False),
    }
    return {
        "check_type": "lab_exploit_poc",
        "target": target,
        "command": f"Lab PoC {exploit_type} on {param}",
        "returncode": 0,
        "stdout": json.dumps(output, indent=2),
        "stderr": "",
        "timed_out": False,
    }


def _check_har_automated_probes(file_path: str | None) -> dict:
    if not file_path:
        raise WebTargetError("har_automated_probes requires a file_path to a traffic export.")
    try:
        report = analyze_traffic_file(file_path)
    except (HarAnalysisError, TrafficImportError) as exc:
        raise WebTargetError(str(exc)) from exc

    results = []
    for item in report.get("recommended_probes", [])[:12]:
        check_type = item["check_type"]
        probe_url = item["url"]
        param = item.get("parameter")
        try:
            if check_type == "sql_error_probe":
                result = _dispatch_input_probe(probe_url, param, location="query", mode="sql")
            elif check_type == "post_form_sql_error":
                result = _dispatch_input_probe(probe_url, param, location="form", mode="sql")
            elif check_type == "post_json_sql_error":
                result = _dispatch_input_probe(probe_url, param, location="json", mode="sql")
            else:
                continue
            parsed = json.loads(result.get("stdout") or "{}")
            if parsed.get("findings"):
                results.append({"probe": item, "findings": parsed.get("findings")})
        except (WebTargetError, ValueError, json.JSONDecodeError):
            continue

    output = {
        "har_file": report["file"],
        "probes_attempted": min(len(report.get("recommended_probes", [])), 12),
        "candidate_findings": results,
        "note": "Candidates only — confirm in Burp Repeater with session context from the export.",
    }
    return {
        "check_type": "har_automated_probes",
        "target": report["file"],
        "command": f"Traffic automated probes on {report['file']}",
        "returncode": 0,
        "stdout": json.dumps(output, indent=2)[:MAX_OUTPUT],
        "stderr": "",
        "timed_out": False,
    }


def _dispatch(ctx: CheckContext, check_type: str) -> dict:
    url = ctx.url
    parameter = ctx.parameter
    wordlist = ctx.wordlist
    file_path = ctx.file_path
    handlers = {
        "http_headers": lambda: _check_http_headers(url),
        "http_methods": lambda: _check_http_methods(url),
        "fetch_resource": lambda: _check_fetch_resource(url),
        "cookie_analysis": lambda: _check_cookie_analysis(url),
        "cors_probe": lambda: _check_cors_probe(url),
        "redirect_chain": lambda: _check_redirect_chain(url),
        "robots_txt": lambda: _check_well_known(url, "/robots.txt", "robots_txt"),
        "security_txt": lambda: _check_well_known(url, "/.well-known/security.txt", "security_txt"),
        "tls_certificate": lambda: _check_tls_certificate(url),
        "technology_fingerprint": lambda: _check_technology_fingerprint(url),
        "subdomain_enum": lambda: _check_subdomain_enum(url),
        "directory_bruteforce": lambda: _check_directory_bruteforce(url, wordlist),
        "api_discovery": lambda: _check_api_discovery(url, wordlist),
        "common_path_probe": lambda: _check_common_path_probe(url),
        "parameter_reflection": lambda: _dispatch_input_probe(url, parameter, location="query", mode="reflection"),
        "sql_error_probe": lambda: _dispatch_input_probe(url, parameter, location="query", mode="sql"),
        "xss_reflection_probe": lambda: _dispatch_input_probe(url, parameter, location="query", mode="xss"),
        "post_form_reflection": lambda: _dispatch_input_probe(url, parameter, location="form", mode="reflection"),
        "post_form_sql_error": lambda: _dispatch_input_probe(url, parameter, location="form", mode="sql"),
        "post_form_xss_reflection": lambda: _dispatch_input_probe(url, parameter, location="form", mode="xss"),
        "post_json_reflection": lambda: _dispatch_input_probe(url, parameter, location="json", mode="reflection"),
        "post_json_sql_error": lambda: _dispatch_input_probe(url, parameter, location="json", mode="sql"),
        "post_json_xss_reflection": lambda: _dispatch_input_probe(url, parameter, location="json", mode="xss"),
        "analyze_har_file": lambda: _check_analyze_har_file(file_path),
        "analyze_burp_xml_file": lambda: _check_analyze_burp_xml_file(file_path),
        "analyze_traffic_file": lambda: _check_analyze_traffic_file(file_path),
        "har_automated_probes": lambda: _check_har_automated_probes(file_path),
        "idor_dual_session_check": lambda: _check_idor_dual_session(ctx),
        "nuclei_web_scan": lambda: _check_nuclei_web_scan(url),
        "burp_proxy_ping": lambda: _check_burp_proxy_ping(ctx),
        "lab_exploit_poc": lambda: _check_lab_exploit_poc(ctx),
    }
    return handlers[check_type]()


def run_check(
    check_type: str,
    url: str | None = None,
    parameter: str | None = None,
    wordlist: str | None = None,
    file_path: str | None = None,
    *,
    use_burp_proxy: bool = False,
    burp_proxy_url: str | None = None,
    session_cookie_a: str | None = None,
    session_cookie_b: str | None = None,
    resource_id_a: str | None = None,
    resource_id_b: str | None = None,
    exploit_type: str | None = None,
    confirm_lab_exploit: bool = False,
) -> dict:
    global _ACTIVE_CTX
    if check_type not in ALLOWED_CHECKS:
        raise ValueError(f"Unknown web check: {check_type}")
    clean_url = validate_url(url) if check_type not in URL_OPTIONAL_CHECKS else (url or "")
    ctx = CheckContext(
        url=clean_url,
        parameter=parameter,
        wordlist=wordlist,
        file_path=file_path,
        use_burp_proxy=use_burp_proxy,
        burp_proxy_url=burp_proxy_url or DEFAULT_BURP_PROXY,
        session_cookie_a=session_cookie_a,
        session_cookie_b=session_cookie_b,
        resource_id_a=resource_id_a,
        resource_id_b=resource_id_b,
        exploit_type=exploit_type,
        confirm_lab_exploit=confirm_lab_exploit,
    )
    _ACTIVE_CTX = ctx
    try:
        return _dispatch(ctx, check_type)
    finally:
        _ACTIVE_CTX = None
