"""Specialist agent for web application security and bug bounty methodology."""

import json
from llm_config import MODEL
from web_security_tools import ALLOWED_CHECKS, URL_OPTIONAL_CHECKS, WebTargetError, run_check, validate_url

SYSTEM_PROMPT = f"""You are CyberProbe's Web Application Security Agent for authorized bug bounty and web app testing.

## Workflow phases

**Phase 1 — Recon**: subdomain_enum, directory_bruteforce, api_discovery, common_path_probe, technology_fingerprint, nuclei_web_scan

**Phase 2 — Passive**: http_headers, cookie_analysis, cors_probe, tls_certificate, robots_txt

**Phase 3 — Burp integration**
- Export traffic: Burp → Save items → HAR or XML
- analyze_traffic_file: auto-detect HAR/XML and inventory endpoints + recommended probes
- analyze_burp_xml_file / analyze_har_file: format-specific imports
- har_automated_probes: run safe SQL probes on discovered parameters
- burp_proxy_ping: verify Burp listener before routing traffic
- Set use_burp_proxy=true to send HTTP/curl checks through Burp (default http://127.0.0.1:8080)

**Phase 4 — Input manipulation (detection only)**
GET: parameter_reflection, sql_error_probe, xss_reflection_probe
POST form: post_form_*
POST JSON: post_json_*

**Phase 5 — Access control**
- idor_dual_session_check: needs resource_id_a, resource_id_b, session_cookie_a, session_cookie_b
- Tests if session B can access session A's resource (A01 Broken Access Control)

**Phase 6 — Lab exploit PoC (gated)**
- lab_exploit_poc: requires confirm_lab_exploit=true AND terminal yes/no confirmation
- exploit_type: sql_union_probe | xss_script_probe | path_traversal_probe
- Only on authorized lab targets

## Approved checks
{chr(10).join(f'- {name}: {desc}' for name, desc in ALLOWED_CHECKS.items())}

## Rules
- Traffic import checks use file_path only (no url).
- use_burp_proxy routes Python HTTP and curl through Burp for manual inspection in Proxy history.
- Never skip lab_exploit_poc gating. SQL/XSS/IDOR hits are candidates until Burp confirms.

## Response format (every turn)
1. **Summary** — what you ran and what was found (plain language for beginners).
2. **Why it matters** — security impact in simple terms.
3. **## NEXT MOVES** — exactly 3–5 numbered options the user can pick next (short, actionable).
"""

TOOLS = [{
    "type": "function",
    "function": {
        "name": "run_web_check",
        "description": "Run one approved web application security check.",
        "parameters": {
            "type": "object",
            "properties": {
                "check_type": {"type": "string", "enum": list(ALLOWED_CHECKS)},
                "url": {"type": "string", "description": "http(s) URL (not needed for traffic import checks)."},
                "file_path": {"type": "string", "description": "Path to .har or Burp .xml export."},
                "parameter": {"type": "string", "description": "Parameter/field name for input or IDOR probes."},
                "wordlist": {"type": "string", "enum": ["common_dirs", "api_paths"]},
                "use_burp_proxy": {"type": "boolean", "description": "Route HTTP traffic through Burp proxy."},
                "burp_proxy_url": {"type": "string", "description": "Burp proxy URL, default http://127.0.0.1:8080."},
                "session_cookie_a": {"type": "string", "description": "Cookie header for user/session A."},
                "session_cookie_b": {"type": "string", "description": "Cookie header for user/session B."},
                "resource_id_a": {"type": "string", "description": "Resource ID owned by session A."},
                "resource_id_b": {"type": "string", "description": "Resource ID owned by session B."},
                "exploit_type": {
                    "type": "string",
                    "enum": ["sql_union_probe", "xss_script_probe", "path_traversal_probe"],
                },
                "confirm_lab_exploit": {
                    "type": "boolean",
                    "description": "Required true for lab_exploit_poc after user authorizes.",
                },
            },
            "required": ["check_type"],
        },
    },
}]


class WebSecurityAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def _execute_tool_call(self, call):
        args = json.loads(call.function.arguments or "{}")
        check_type = args.get("check_type")
        try:
            url = None if check_type in URL_OPTIONAL_CHECKS else validate_url(args.get("url"))
            return run_check(
                check_type,
                url=url,
                parameter=args.get("parameter"),
                wordlist=args.get("wordlist"),
                file_path=args.get("file_path"),
                use_burp_proxy=bool(args.get("use_burp_proxy")),
                burp_proxy_url=args.get("burp_proxy_url"),
                session_cookie_a=args.get("session_cookie_a"),
                session_cookie_b=args.get("session_cookie_b"),
                resource_id_a=args.get("resource_id_a"),
                resource_id_b=args.get("resource_id_b"),
                exploit_type=args.get("exploit_type"),
                confirm_lab_exploit=bool(args.get("confirm_lab_exploit")),
            )
        except (WebTargetError, ValueError) as exc:
            return {"error": str(exc)}

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(
            model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto",
        )
        reply = response.choices[0].message
        turn_log = {
            "agent": "web_security", "tool_type": None, "target": None, "command": None,
            "returncode": None, "stdout": None, "stderr": None, "timed_out": False,
        }
        while reply.tool_calls:
            self.messages.append(reply)
            for call in reply.tool_calls:
                payload = self._execute_tool_call(call)
                turn_log.update({
                    "tool_type": payload.get("check_type"),
                    "target": payload.get("target"),
                    "command": payload.get("command"),
                    "returncode": payload.get("returncode"),
                    "stdout": payload.get("stdout"),
                    "stderr": payload.get("stderr"),
                    "timed_out": payload.get("timed_out", False),
                })
                self.messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(payload)})
            response = self.client.chat.completions.create(
                model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto",
            )
            reply = response.choices[0].message
        self.messages.append(reply)
        return reply.content or "The web security checks finished, but the model returned no summary.", turn_log
