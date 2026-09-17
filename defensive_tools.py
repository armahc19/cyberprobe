"""Read-only defensive security checks for the local host.

Commands and arguments are fixed here so the agent cannot execute arbitrary
shell commands. Response actions belong in a separate, approval-gated layer.
"""

from __future__ import annotations

import os
import shutil
import subprocess


ALLOWED_CHECKS = {
    "recent_system_logs": (
        ["journalctl", "-n", "100", "--no-pager"],
        "Review the most recent system journal events.",
    ),
    "authentication_logs": (
        ["journalctl", "-n", "100", "--no-pager", "_COMM=sshd"],
        "Review recent SSH authentication events.",
    ),
    "failed_logins": (
        ["lastb", "-n", "25"],
        "Review recent failed login records.",
    ),
    "process_snapshot": (
        ["ps", "-eo", "pid,ppid,user,stat,%cpu,%mem,lstart,comm", "--sort=-%cpu"],
        "Inspect running processes and resource usage.",
    ),
    "network_connections": (
        ["ss", "-tupn"],
        "Inspect active network connections and owning processes.",
    ),
    "listening_services": (
        ["ss", "-tulpen"],
        "Inspect listening TCP and UDP services.",
    ),
    "failed_services": (
        ["systemctl", "--no-pager", "--failed"],
        "Find systemd services that have failed.",
    ),
    "service_inventory": (
        ["systemctl", "--no-pager", "list-units", "--type=service", "--state=running"],
        "Inventory currently running system services.",
    ),
    "firewall_ufw": (
        ["ufw", "status", "verbose"],
        "Inspect UFW firewall status and rules.",
    ),
    "firewall_nftables": (
        ["nft", "list", "ruleset"],
        "Inspect nftables firewall rules.",
    ),
    "scheduled_tasks": (
        ["systemctl", "--no-pager", "list-timers", "--all"],
        "Inspect systemd scheduled timers.",
    ),
    "audit_status": (
        ["auditctl", "-s"],
        "Inspect Linux audit subsystem status.",
    ),
    "file_metadata": (
        ["stat", "--"],
        "Inspect ownership, permissions, size, and timestamps for a file.",
    ),
    "file_hash": (
        ["sha256sum", "--"],
        "Calculate a SHA-256 hash for a supplied file.",
    ),
}

MAX_TIMEOUT_SECONDS = 90
MAX_OUTPUT_CHARS = 12000

INVESTIGATION_CHECKS = (
    "recent_system_logs",
    "authentication_logs",
    "failed_logins",
    "process_snapshot",
    "network_connections",
    "listening_services",
    "failed_services",
    "service_inventory",
    "firewall_ufw",
    "firewall_nftables",
    "scheduled_tasks",
    "audit_status",
)


def _validate_path(target: str | None) -> str:
    if not target:
        raise ValueError("This defensive check requires a file path.")
    if "\x00" in target or target.startswith("-") or len(target) > 4096:
        raise ValueError("The file path is invalid.")
    return os.path.abspath(target)


def run_check(check_type: str, target: str | None = None) -> dict:
    if check_type not in ALLOWED_CHECKS:
        raise ValueError(f"Unknown defensive check: {check_type}")

    command = list(ALLOWED_CHECKS[check_type][0])
    if check_type in {"file_metadata", "file_hash"}:
        command.append(_validate_path(target))
    elif target:
        raise ValueError(f"The '{check_type}' check does not accept a target.")

    binary = command[0]
    if shutil.which(binary) is None:
        return {
            "check_type": check_type,
            "command": " ".join(command),
            "returncode": 127,
            "stdout": "",
            "stderr": f"Required tool not installed: {binary}",
            "timed_out": False,
        }

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=MAX_TIMEOUT_SECONDS,
        )
        return {
            "check_type": check_type,
            "command": " ".join(command),
            "returncode": result.returncode,
            "stdout": result.stdout[:MAX_OUTPUT_CHARS],
            "stderr": result.stderr[:3000],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "check_type": check_type,
            "command": " ".join(command),
            "returncode": -1,
            "stdout": (exc.stdout or "")[:MAX_OUTPUT_CHARS],
            "stderr": (exc.stderr or "")[:3000],
            "timed_out": True,
        }


def run_investigation_snapshot() -> dict:
    """Collect a bounded, read-only snapshot for defensive correlation."""
    results = []
    for check_type in INVESTIGATION_CHECKS:
        result = run_check(check_type)
        result["stdout"] = result.get("stdout", "")[:4000]
        result["stderr"] = result.get("stderr", "")[:1000]
        results.append(result)
    return {
        "investigation": "local_defensive_snapshot",
        "checks": results,
    }
