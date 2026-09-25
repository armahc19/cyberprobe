"""Approval-gated bridge to the local Metasploit module database."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from urllib.parse import urlparse

MAX_OUTPUT = 16000
MODULE_RE = re.compile(r"^[a-z0-9_./-]+$")


def discover_modules(query: str) -> dict:
    """Ask Metasploit for matching installed modules; no module is executed."""
    if not shutil.which("msfconsole"):
        raise RuntimeError("msfconsole is not installed or is not on PATH.")
    query = (query or "").strip()
    if not query or len(query) > 200 or not re.fullmatch(r"[A-Za-z0-9 .:_-]+", query):
        raise ValueError("A simple vulnerability, product, or CVE search phrase is required.")
    result = subprocess.run(
        ["msfconsole", "-q", "-x", f"search {query}; exit -y"],
        capture_output=True, text=True, timeout=120,
    )
    return {"query": query, "returncode": result.returncode,
            "stdout": result.stdout[-MAX_OUTPUT:], "stderr": result.stderr[-4000:]}


def module_installed(module: str) -> bool:
    result = subprocess.run(
        ["msfconsole", "-q", "-x", f"info {module}; exit -y"],
        capture_output=True, text=True, timeout=120,
    )
    text = (result.stdout + result.stderr).lower()
    return result.returncode == 0 and module.lower() in text and "not found" not in text


def _target(value: str) -> str:
    value = (value or "").strip()
    if not value or any(ch in value for ch in "\r\n;|&$`'\""):
        raise ValueError("A single explicit IP address or hostname is required.")
    candidate = urlparse(value).hostname or value
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", candidate):
            raise ValueError("Target must be a valid IP address or hostname.")
    return candidate


def run_approved_module(*, target: str, module: str, rport: int | None = None,
                        payload: str | None = None) -> dict:
    target = _target(target)
    module = (module or "").strip()
    if not MODULE_RE.fullmatch(module) or not module_installed(module):
        raise ValueError("Module was not found in the local Metasploit installation.")
    if not shutil.which("msfconsole"):
        raise RuntimeError("msfconsole is not installed or is not on PATH.")
    if rport is not None and not 1 <= int(rport) <= 65535:
        raise ValueError("rport must be between 1 and 65535.")
    if payload and not MODULE_RE.fullmatch(payload):
        raise ValueError("Payload must be a simple allowlisted Metasploit name.")

    details = [f"use {module}", f"set RHOSTS {target}"]
    if rport is not None:
        details.append(f"set RPORT {int(rport)}")
    if payload:
        details.append(f"set PAYLOAD {payload}")
    details.extend(["check", "exploit -j", "sleep 3", "sessions -l", "exit -y"])
    script = "; ".join(details)
    answer = input(
        f"\n[CyberProbe] Metasploit action requested\n  target: {target}\n"
        f"  module: {module}\n  payload: {payload or '(module default)'}\n"
        "This may affect the target. Authorized testing only. Continue? (yes/no): "
    ).strip().lower()
    if answer not in {"y", "yes"}:
        return {"approved": False, "target": target, "module": module,
                "command": "msfconsole (declined)", "returncode": 0,
                "stdout": "User declined Metasploit execution.", "stderr": ""}

    command = ["msfconsole", "-q", "-x", script]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        return {"approved": True, "target": target, "module": module,
                "command": "msfconsole -q -x <approved script>", "returncode": -1,
                "stdout": (exc.stdout or "")[-MAX_OUTPUT:],
                "stderr": "Metasploit timed out.", "timed_out": True}
    return {"approved": True, "target": target, "module": module,
            "command": "msfconsole -q -x <approved script>",
            "returncode": result.returncode,
            "stdout": result.stdout[-MAX_OUTPUT:], "stderr": result.stderr[-4000:],
            "timed_out": False}
