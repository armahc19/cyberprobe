"""Beginner-friendly next-step suggestions after each CyberProbe turn."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

NEXT_MOVES_HEADER = re.compile(r"^#{1,3}\s*next moves\b", re.I)
NUMBERED_LINE = re.compile(r"^\s*(\d+)[.)]\s+(.+)$")


@dataclass
class SessionContext:
    last_user_message: str = ""
    last_reply: str = ""
    last_agent: str | None = None
    last_target: str | None = None
    last_tool_type: str | None = None
    suggestions: list["Suggestion"] = field(default_factory=list)


@dataclass
class Suggestion:
    number: int
    label: str
    command: str


def extract_url(text: str) -> str | None:
    match = re.search(r"https?://[^\s\])>\"']+", text or "")
    return match.group(0).rstrip(".,;") if match else None


def extract_suggestions_from_reply(reply: str) -> list[Suggestion]:
    """Parse a ## NEXT MOVES numbered list from agent text."""
    if not reply:
        return []
    lines = reply.splitlines()
    collecting = False
    found: list[Suggestion] = []
    for line in lines:
        if NEXT_MOVES_HEADER.match(line.strip()):
            collecting = True
            continue
        if collecting:
            stripped = line.strip()
            if stripped.startswith("#") and found:
                break
            match = NUMBERED_LINE.match(line)
            if match:
                number = int(match.group(1))
                label = match.group(2).strip()
                found.append(Suggestion(number=number, label=label, command=label))
            elif stripped == "" and found:
                break
    # Renumber sequentially for menu display
    return [Suggestion(number=i + 1, label=s.label, command=s.command) for i, s in enumerate(found)]


def build_fallback_suggestions(
    *,
    reply: str,
    agent: str | None,
    target: str | None,
    tool_type: str | None,
    user_message: str,
) -> list[Suggestion]:
    """Rule-based suggestions when the agent did not emit a NEXT MOVES block."""
    target = target or extract_url(user_message) or extract_url(reply) or "the target"
    host = urlparse(target).netloc if target.startswith("http") else target
    suggestions: list[tuple[str, str]] = []

    if agent == "web_security" or "http" in (target or ""):
        suggestions.extend([
            (
                "Run deeper input probes (SQL + XSS on GET parameters)",
                f"run sql and xss probes on {target}",
            ),
            (
                "Run POST/JSON input probes if the app has forms or APIs",
                f"run post json sql and xss probes on {target}",
            ),
            (
                "Scan with nuclei web templates for known misconfigs/CVEs",
                f"run nuclei web scan on {target}",
            ),
            (
                "Import Burp HAR/XML and auto-probe discovered parameters",
                "analyze my Burp export — tell me the file path to your .har or .xml",
            ),
            (
                "Generate a beginner-friendly security report",
                f"create a prioritized web security report for {target}",
            ),
        ])
    elif agent == "recon":
        suggestions.extend([
            (
                "Identify service versions on open ports",
                f"run version scan on {host}",
            ),
            (
                "Hand results to vulnerability assessment",
                f"assess vulnerabilities for {host} based on the recon results above",
            ),
            (
                "Check web headers if HTTP ports were found",
                f"check http headers on http://{host}",
            ),
            (
                "Generate a consolidated report",
                f"create a security report for {host}",
            ),
        ])
    elif agent == "network_security":
        suggestions.extend([
            ("Inspect listening ports in detail", "show listening ports and explain risks"),
            ("Review firewall rules", "inspect firewall status and explain exposure"),
            ("Check DNS resolver configuration", "show dns configuration"),
        ])
    elif agent == "linux":
        suggestions.extend([
            ("Review running processes for anomalies", "show running processes and flag suspicious ones"),
            ("Check failed login attempts in logs", "inspect auth logs for failed logins"),
            ("Review users and permissions", "list users and highlight permission risks"),
        ])
    else:
        suggestions.extend([
            ("Run a quick web check on a URL you provide", "run checks on my website — I will paste the URL"),
            ("Scan a lab host/IP on your network", "scan my lab target — I will paste the IP or hostname"),
            ("See which security tools are installed", "check setup"),
        ])

    if tool_type in {"analyze_traffic_file", "analyze_har_file", "analyze_burp_xml_file"}:
        suggestions.insert(0, (
            "Run automated probes on parameters found in the export",
            "run har automated probes on the same traffic file I just analyzed",
        ))

    return [
        Suggestion(number=i + 1, label=label, command=command)
        for i, (label, command) in enumerate(suggestions[:5])
    ]


def build_suggestions(
    *,
    reply: str,
    agent: str | None,
    target: str | None,
    tool_type: str | None,
    user_message: str,
) -> list[Suggestion]:
    parsed = extract_suggestions_from_reply(reply)
    if parsed:
        return parsed[:5]
    return build_fallback_suggestions(
        reply=reply,
        agent=agent,
        target=target,
        tool_type=tool_type,
        user_message=user_message,
    )


def format_suggestions_menu(suggestions: list[Suggestion]) -> str:
    if not suggestions:
        return ""
    lines = [
        "",
        "╔══════════════════════════════════════════════════════════════════╗",
        "║  SUGGESTED NEXT MOVES — pick a number or type your own command   ║",
        "╚══════════════════════════════════════════════════════════════════╝",
    ]
    for item in suggestions:
        wrapped = item.label
        if len(wrapped) > 64:
            wrapped = wrapped[:61] + "..."
        lines.append(f"  {item.number}. {wrapped}")
    lines.append("  0. Skip — return to cyberprobe> prompt")
    lines.append("")
    return "\n".join(lines)


def resolve_menu_choice(choice: str, suggestions: list[Suggestion]) -> str | None:
    """Return the command for a numeric menu choice, or None to skip."""
    choice = choice.strip()
    if not choice or choice == "0":
        return None
    if choice.isdigit():
        index = int(choice)
        for item in suggestions:
            if item.number == index:
                return item.command
        return None
    return choice
