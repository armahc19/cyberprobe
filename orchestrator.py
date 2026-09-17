"""
orchestrator.py

Top-level router for CyberProbe. Understands user intent and delegates to
the Recon Agent (network scanning), Forensics Agent (file analysis), or
Linux System Agent (host inspection).
Specialist agents own their tool execution; the orchestrator only routes.
"""

import json

from forensics_agent import ForensicsAgent
from defensive_agent import DefensiveSecurityAgent
from llm_config import MODEL, get_groq_client
from linux_agent import LinuxAgent
from network_security_agent import NetworkSecurityAgent
from logger import log_turn, new_session_id
from recon_agent import ReconAgent
from web_security_agent import WebSecurityAgent
from vulnerability_agent import VulnerabilityAssessmentAgent
from report_agent import ReportAgent
from terminal_agent import TerminalAgent
from session_guide import SessionContext, build_suggestions, extract_url, format_suggestions_menu

SYSTEM_PROMPT = """You are the Orchestrator for CyberProbe, a beginner-friendly
cybersecurity assistant. Your job is to understand what the user wants and
route their request to the right specialist agent.

IMPORTANT — Beginner guidance:
- Assume the user is a complete beginner unless they say otherwise.
- After delegation, the specialist will explain results in plain language.
- When you answer directly (no delegation), always end with a section titled
  exactly "## NEXT MOVES" followed by 3–5 numbered, actionable options the
  user can pick on the next turn (short labels they can type or choose by number).

You have nine specialist agents:

1. **Recon Agent** -- network reconnaissance on user-supplied targets.
   Use for: scanning IPs/hostnames, finding open ports, detecting services,
   OS detection, "what's running on this machine?", nmap-related requests.

2. **Forensics Agent** -- file, memory, disk, and filesystem forensics.
   Use for: analyzing files or forensic images, extracting metadata, hashing,
   memory analysis, filesystem inspection, data carving, and deleted-file recovery.

3. **Linux System Agent** -- Linux host inspection and system status.
   Use for: system information, processes, services, storage, permissions,
   users, networking, logs, and health checks on a Linux machine.

4. **Web Security Agent** -- web application security and bug bounty methodology.
   Use for: HTTP analysis, subdomain/dir/API discovery, OWASP-style input probes,
   cookie/CORS/TLS checks, technology fingerprinting, and Burp guidance.

5. **Network Security Agent** -- local network posture analysis.
   Use for: interfaces, listening ports, routes, DNS, firewall exposure,
   packet samples, traffic investigation, and network anomalies.

6. **Vulnerability Assessment Agent** -- evidence-based vulnerability and configuration assessment.
   Use for: CVE/CPE correlation, safe vulnerability checks, Lynis, risk, and remediation.

7. **Report Agent** -- produces prioritized Markdown or JSON security reports.
   Use for: consolidating findings, evidence, risk, remediation, and validation.

8. **Defensive Security Agent** -- defensive monitoring and incident investigation.
   Use for: logs, authentication anomalies, suspicious processes, services,
   connections, firewall posture, scheduled tasks, IOC-oriented file checks,
   evidence preservation, threat hunting, and security posture.

Routing rules:
- If the request clearly involves network scanning or a target IP/hostname,
  delegate to the Recon Agent.
- If the request clearly involves analyzing a file or file path,
  delegate to the Forensics Agent.
- If the request clearly involves inspecting a Linux system or host state,
  delegate to the Linux System Agent.
- If the request clearly involves assessing a web application or URL,
  delegate to the Web Security Agent.
- If the request clearly involves network posture or local traffic,
  delegate to the Network Security Agent.
- If the request clearly involves vulnerabilities, CVEs, risk, or security
  configuration assessment, delegate to the Vulnerability Assessment Agent.
- If the request clearly involves monitoring, suspicious activity, incidents,
  threat hunting, IOCs, firewall review, evidence preservation, or defensive
   posture, delegate to the Defensive Security Agent.
- If the request asks CyberProbe to navigate folders, create/edit/delete files,
  manage packages, permissions, processes, services, or search local files,
  delegate to the Terminal Operations Agent.
- If the request clearly asks for a report or consolidated assessment,
  delegate to the Report Agent.
- If the user mixes both (e.g. "scan 192.168.1.5 and also check this PDF"),
  pick the primary intent for this turn and mention the other in your reply
  after delegation, or ask which they want first.
- If the request is ambiguous, ask ONE short clarifying question instead of
  guessing.
- If the user asks a general question about CyberProbe capabilities (no scan
  or file analysis needed), answer directly in plain language without
  delegating.

When delegating, pass the user's full request (including any target or file
path they mentioned) in the `request` field so the specialist has full context.

Never run scans or forensics tools yourself -- always delegate.
"""

ROUTING_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "delegate_to_defensive_security_agent",
            "description": "Hand off to the Defensive Security Agent for read-only monitoring, threat detection, incident investigation, threat hunting, IOC checks, evidence preservation, and defensive posture review.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_recon_agent",
            "description": (
                "Hand off to the Recon Agent for network scanning, port "
                "discovery, service detection, or OS detection on user-supplied targets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {
                        "type": "string",
                        "description": (
                            "The user's network recon request, including any "
                            "target IP or hostname they mentioned."
                        ),
                    }
                },
                "required": ["request"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_forensics_agent",
            "description": (
                "Hand off to the Forensics Agent for file, memory-image, disk-image, "
                "filesystem, carving, and deleted-file recovery analysis."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {
                        "type": "string",
                        "description": (
                            "The user's file forensics request, including any "
                            "file path they mentioned."
                        ),
                    }
                },
                "required": ["request"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_report_agent",
            "description": "Hand off supplied security results to the Report Agent for a prioritized report.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_vulnerability_assessment_agent",
            "description": "Hand off for evidence-based vulnerability and configuration assessment.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_network_security_agent",
            "description": "Hand off to the Network Security Agent for read-only network posture checks.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_web_security_agent",
            "description": "Hand off to the Web Security Agent for web app security, OWASP checks, recon, and input probing.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_linux_agent",
            "description": (
                "Hand off to the Linux System Agent for Linux host inspection, "
                "processes, services, logs, networking, disks, permissions, and health checks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "request": {
                        "type": "string",
                        "description": (
                            "The user's Linux inspection request, including any "
                            "service, file, user, or host they mentioned."
                        ),
                    }
                },
                "required": ["request"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delegate_to_terminal_agent",
            "description": "Hand off local terminal navigation, file operations, package management, permissions, processes, services, and file searching.",
            "parameters": {"type": "object", "properties": {"request": {"type": "string"}}, "required": ["request"]},
        },
    },
]


class Orchestrator:
    def __init__(self):
        self.client = get_groq_client()
        self.session_id = new_session_id()
        self.defensive_agent = DefensiveSecurityAgent(self.client)
        self.recon_agent = ReconAgent(self.client)
        self.forensics_agent = ForensicsAgent(self.client)
        self.linux_agent = LinuxAgent(self.client)
        self.web_security_agent = WebSecurityAgent(self.client)
        self.network_security_agent = NetworkSecurityAgent(self.client)
        self.vulnerability_agent = VulnerabilityAssessmentAgent(self.client)
        self.report_agent = ReportAgent(self.client)
        self.terminal_agent = TerminalAgent(self.client)
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        self.session = SessionContext()

    def _record_turn(self, user_message: str, reply: str, turn_log: dict | None = None) -> None:
        turn_log = turn_log or {}
        self.session.last_user_message = user_message
        self.session.last_reply = reply or ""
        self.session.last_agent = turn_log.get("agent")
        self.session.last_target = turn_log.get("target")
        self.session.last_tool_type = turn_log.get("tool_type")
        self.session.suggestions = build_suggestions(
            reply=self.session.last_reply,
            agent=self.session.last_agent,
            target=self.session.last_target,
            tool_type=self.session.last_tool_type,
            user_message=user_message,
        )

    def get_suggestions_menu(self) -> str:
        return format_suggestions_menu(self.session.suggestions)

    def resolve_follow_up(self, choice: str) -> str | None:
        from session_guide import resolve_menu_choice
        command = resolve_menu_choice(choice, self.session.suggestions)
        if command is None:
            return None
        # Give the specialist full context when user picks a numbered suggestion.
        if choice.strip().isdigit() and self.session.last_reply:
            return (
                f"Continue the assessment. Previous context:\n{self.session.last_reply[:2000]}\n\n"
                f"User chose next step: {command}"
            )
        return command

    def _call_model(self):
        return self.client.chat.completions.create(
            model=MODEL,
            messages=self.messages,
            tools=ROUTING_TOOLS,
            tool_choice="auto",
        )

    def _delegate(self, tool_name: str, request: str) -> tuple[str, dict]:
        if tool_name == "delegate_to_terminal_agent":
            print("\n[Orchestrator → Terminal Operations Agent]")
            return self.terminal_agent.send(request)

        if tool_name == "delegate_to_defensive_security_agent":
            print("\n[Orchestrator → Defensive Security Agent]")
            return self.defensive_agent.send(request)

        if tool_name == "delegate_to_recon_agent":
            print("\n[Orchestrator → Recon Agent]")
            return self.recon_agent.send(request)

        if tool_name == "delegate_to_forensics_agent":
            print("\n[Orchestrator → Forensics Agent]")
            return self.forensics_agent.send(request)

        if tool_name == "delegate_to_linux_agent":
            print("\n[Orchestrator → Linux System Agent]")
            return self.linux_agent.send(request)

        if tool_name == "delegate_to_web_security_agent":
            print("\n[Orchestrator → Web Security Agent]")
            return self.web_security_agent.send(request)

        if tool_name == "delegate_to_network_security_agent":
            print("\n[Orchestrator → Network Security Agent]")
            return self.network_security_agent.send(request)

        if tool_name == "delegate_to_vulnerability_assessment_agent":
            print("\n[Orchestrator → Vulnerability Assessment Agent]")
            return self.vulnerability_agent.send(request)

        if tool_name == "delegate_to_report_agent":
            print("\n[Orchestrator → Report Agent]")
            return self.report_agent.send(request)

        return f"Internal routing error: unknown delegation '{tool_name}'.", {"agent": "orchestrator"}

    def _run_assessment_workflow(self, request: str) -> str:
        """Run the evidence pipeline for an explicit end-to-end assessment."""
        recon_text, _ = self.recon_agent.send(request)
        assessment_request = (
            "Assess the following Recon Agent results. Correlate products and "
            "versions with trusted vulnerability intelligence when appropriate. "
            "Do not treat version matches as confirmation.\n\n" + recon_text
        )
        vulnerability_text, _ = self.vulnerability_agent.send(assessment_request)
        report_request = (
            "Create a prioritized security report from these Recon and "
            "Vulnerability Assessment results. Preserve evidence and confidence.\n\n"
            "RECON:\n" + recon_text + "\n\nASSESSMENT:\n" + vulnerability_text
        )
        report_text, _ = self.report_agent.send(report_request)
        return report_text

    def _run_web_assessment_workflow(self, request: str) -> str:
        """Run phased web application security assessment."""
        web_request = (
            "Run a full web application security assessment using your methodology.\n"
            "Phase 1 Recon: subdomain_enum, common_path_probe, api_discovery, technology_fingerprint, nuclei_web_scan.\n"
            "Phase 2 Passive: http_headers, cookie_analysis, cors_probe, robots_txt, tls_certificate.\n"
            "Phase 3 Burp: analyze_traffic_file if HAR/XML path given; use_burp_proxy when Burp is running.\n"
            "Phase 4 Input: GET, post_form_*, post_json_* probes. Phase 5 IDOR if two sessions available.\n"
            "Phase 4: Provide Burp Suite next steps and OWASP Top 10 mapping.\n\n"
            + request
        )
        web_text, _ = self.web_security_agent.send(web_request)
        report_request = (
            "Create a bug bounty style security report from these web application "
            "assessment results. Include scope, findings, evidence, severity, "
            "confidence, OWASP category, remediation, and manual validation steps.\n\n"
            + web_text
        )
        report_text, _ = self.report_agent.send(report_request)
        return report_text

    def send(self, user_message: str) -> str:
        lowered = user_message.lower()
        if any(phrase in lowered for phrase in ("full assessment", "end-to-end assessment", "complete assessment")):
            print("\n[CyberProbe workflow: Recon → Vulnerability Assessment → Report]")
            try:
                reply = self._run_assessment_workflow(user_message)
                self._record_turn(user_message, reply, {"agent": "workflow", "target": extract_url(user_message)})
                return reply
            except Exception as error:
                return f"The assessment workflow could not complete: {error}"

        if any(
            phrase in lowered
            for phrase in (
                "full web assessment",
                "web app assessment",
                "web application assessment",
                "bug bounty assessment",
                "owasp assessment",
            )
        ):
            print("\n[CyberProbe workflow: Web Security → Report]")
            try:
                reply = self._run_web_assessment_workflow(user_message)
                self._record_turn(user_message, reply, {"agent": "workflow", "target": extract_url(user_message)})
                return reply
            except Exception as error:
                return f"The web assessment workflow could not complete: {error}"

        self.messages.append({"role": "user", "content": user_message})

        response = self._call_model()
        reply = response.choices[0].message

        if reply.tool_calls:
            self.messages.append(reply)
            tool_call = reply.tool_calls[0]
            args = json.loads(tool_call.function.arguments)
            request = args.get("request", user_message)

            content, turn_log = self._delegate(tool_call.function.name, request)

            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": (content or "")[:500],
            })

            log_turn(
                session_id=self.session_id,
                user_message=user_message,
                agent=turn_log.get("agent"),
                scan_type=turn_log.get("scan_type"),
                target=turn_log.get("target"),
                tool_type=turn_log.get("tool_type"),
                file_path=turn_log.get("file_path"),
                file_hash=turn_log.get("file_hash"),
                command=turn_log.get("command"),
                returncode=turn_log.get("returncode"),
                stdout=turn_log.get("stdout"),
                stderr=turn_log.get("stderr"),
                timed_out=turn_log.get("timed_out", False),
                declined_sudo=turn_log.get("declined_sudo", False),
                agent_explanation=content,
                findings=turn_log.get("findings", []),
            )
            self._record_turn(user_message, content or "", turn_log)
            return content or ""

        self.messages.append(reply)
        content = reply.content or ""
        log_turn(
            session_id=self.session_id,
            user_message=user_message,
            agent="orchestrator",
            scan_type=None,
            target=None,
            tool_type=None,
            file_path=None,
            file_hash=None,
            command=None,
            returncode=None,
            stdout=None,
            stderr=None,
            timed_out=False,
            declined_sudo=False,
            agent_explanation=content,
            findings=[],
        )
        self._record_turn(user_message, content, {"agent": "orchestrator"})
        return content
