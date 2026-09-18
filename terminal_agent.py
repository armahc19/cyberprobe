"""Structured natural-language planning for safe local terminal operations."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from llm_config import MODEL
from terminal_tools import OPERATIONS, run_terminal_operation

PLAN_SYSTEM_PROMPT = f"""You are CyberProbe's terminal intent planner.
Understand the user's natural-language Linux request and return ONLY valid JSON.
Create a plan using one or more operations from this allowlist:

{chr(10).join(f'- {name}: {description}' for name, description in OPERATIONS.items())}

Return exactly this shape:
{{"steps": [{{"operation": "operation_name", "path": "...", "destination": "...", "pattern": "...", "package": "...", "mode": "...", "owner": "...", "group": "...", "pid": "...", "signal": "...", "service": "...", "action": "...", "content": "..."}}]}}

Include only fields needed by each operation. Never return shell commands,
flags, pipelines, or prose. Resolve common locations such as Desktop,
Documents, Downloads, and home using ~/ paths. For a request that is unsafe,
ambiguous, or outside the allowlist, return {{"steps": []}} and an optional
{{"clarification": "question"}} field.
"""

EXPLANATION_PROMPT = """You are CyberProbe's terminal-result explainer. Explain the
validated terminal plan and results plainly and briefly. Say what completed,
what failed, and why. Do not invent commands or claim an operation succeeded
unless its result has returncode 0."""

PLAN_FIELDS = {
    "operation", "path", "destination", "pattern", "content", "package",
    "mode", "owner", "group", "pid", "signal", "service", "action",
}


class TerminalAgent:
    def __init__(self, client):
        self.client = client

    def _make_plan(self, request: str) -> dict:
        response = self.client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": PLAN_SYSTEM_PROMPT},
                {"role": "user", "content": request[:6000]},
            ],
            response_format={"type": "json_object"},
            temperature=0,
        )
        content = response.choices[0].message.content or "{}"
        plan = json.loads(content)
        steps = plan.get("steps", [])
        if not isinstance(steps, list) or len(steps) > 8:
            raise ValueError("The terminal plan is invalid or too large.")
        validated = []
        for step in steps:
            if not isinstance(step, dict) or step.get("operation") not in OPERATIONS:
                raise ValueError("The plan contains an unsupported terminal operation.")
            if set(step) - PLAN_FIELDS:
                raise ValueError("The plan contains an unsupported command field.")
            validated.append({key: value for key, value in step.items() if key in PLAN_FIELDS and value is not None})
        plan["steps"] = validated
        return plan

    def make_current_shell_action(self, request: str) -> dict:
        """Build a shell action for the companion to run in the current shell."""
        plan = self._make_plan(request)
        if not plan.get("steps"):
            return {
                "ok": False,
                "reason": plan.get("clarification", "I could not map that request to an approved terminal operation."),
            }

        commands = []
        for step in plan["steps"]:
            command = _step_to_shell_command(step)
            if not command:
                return {
                    "ok": False,
                    "reason": f"The operation '{step.get('operation')}' cannot run in the current shell yet.",
                }
            commands.append(command)

        return {
            "ok": True,
            "commands": commands,
            "display": "\n".join(commands),
            "risk": _plan_risk(plan["steps"]),
        }

    def _explain(self, request: str, plan: dict, results: list[dict]) -> str:
        try:
            response = self.client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": EXPLANATION_PROMPT},
                    {"role": "user", "content": json.dumps({"request": request, "plan": plan, "results": results})[:7000]},
                ],
                temperature=0,
            )
            return response.choices[0].message.content or "The terminal operations completed."
        except Exception:
            completed = sum(result.get("returncode") == 0 for result in results)
            return f"Completed {completed} of {len(results)} terminal operation(s)."

    def send(self, user_message: str) -> tuple[str, dict]:
        try:
            plan = self._make_plan(user_message)
        except Exception as error:
            return f"I could not create a safe terminal plan: {error}", {"agent": "terminal"}

        if not plan.get("steps"):
            return plan.get("clarification", "I could not map that request to an approved terminal operation."), {"agent": "terminal"}

        results = []
        turn_log = {"agent": "terminal", "tool_type": None, "command": None, "returncode": None, "stdout": None, "stderr": None, "timed_out": False}
        for step in plan["steps"]:
            try:
                result = run_terminal_operation(**{key: value for key, value in step.items() if key != "operation"}, operation=step["operation"])
            except (ValueError, OSError) as error:
                result = {"operation": step["operation"], "returncode": 1, "stdout": "", "stderr": str(error)}
            results.append(result)
            turn_log.update({"tool_type": result.get("operation"), "command": result.get("command"), "returncode": result.get("returncode"), "stdout": result.get("stdout"), "stderr": result.get("stderr"), "timed_out": result.get("timed_out", False)})
            if result.get("returncode") not in {0, None}:
                break

        return self._explain(user_message, plan, results), turn_log


def _quote_path(value: str | None, label: str = "path") -> str:
    if not value or "\x00" in value or len(value) > 4096 or value.startswith("-"):
        raise ValueError(f"A valid {label} is required.")
    return shlex.quote(os.path.abspath(os.path.expanduser(value)))


def _quote_value(value: str | None, label: str = "value") -> str:
    if not value or "\x00" in value or len(value) > 4096:
        raise ValueError(f"A valid {label} is required.")
    return shlex.quote(value)


def _plan_risk(steps: list[dict]) -> str:
    mutating = {"mkdir", "touch", "cp", "mv", "move_matching_files", "rm", "rmdir", "write_file", "apt_update", "apt_install", "apt_remove", "chmod", "chown", "chgrp", "kill"}
    if any(step.get("operation") in mutating for step in steps):
        return "changes-files-or-system"
    if any(step.get("operation") in {"systemctl", "service"} and step.get("action", "status") != "status" for step in steps):
        return "changes-service-state"
    return "read-only"


def _step_to_shell_command(step: dict) -> str | None:
    operation = step.get("operation")
    path = step.get("path")
    destination = step.get("destination")
    pattern = step.get("pattern")
    package = step.get("package")
    mode = step.get("mode")
    owner = step.get("owner")
    group = step.get("group")
    pid = step.get("pid")
    signal = step.get("signal") or "TERM"
    service = step.get("service")
    action = step.get("action") or "status"

    if operation == "pwd":
        return "pwd"
    if operation == "cd":
        directory = os.path.abspath(os.path.expanduser(path or "."))
        if not Path(directory).is_dir():
            raise ValueError(f"Directory not found: {directory}")
        return f"cd -- {shlex.quote(directory)}"
    if operation == "ls":
        return f"ls -la -- {_quote_path(path or '.')}"
    if operation == "tree":
        return f"tree -L 2 {_quote_path(path or '.')}"
    if operation in {"cat", "less", "stat"}:
        return f"{operation} -- {_quote_path(path)}"
    if operation == "head":
        return f"head -n 50 -- {_quote_path(path)}"
    if operation == "tail":
        return f"tail -n 50 -- {_quote_path(path)}"
    if operation == "find":
        return f"find {_quote_path(path or '.')} -maxdepth 3 -iname {_quote_value(pattern or '*', 'search pattern')}"
    if operation == "grep":
        return f"grep -n -I -- {_quote_value(pattern, 'search text')} {_quote_path(path)}"
    if operation in {"locate", "which", "whereis"}:
        value = pattern or package
        return f"{operation} {_quote_value(value, 'command or search pattern')}"
    if operation == "mkdir":
        return f"mkdir -p {_quote_path(path)}"
    if operation == "touch":
        return f"touch {_quote_path(path)}"
    if operation in {"cp", "mv"}:
        return f"{operation} -r {_quote_path(path, 'source path')} {_quote_path(destination, 'destination path')}"
    if operation == "rm":
        return f"rm -r {_quote_path(path)}"
    if operation == "rmdir":
        return f"rmdir {_quote_path(path)}"
    if operation == "nano":
        return f"nano {_quote_path(path)}"
    if operation == "apt_update":
        return "sudo apt-get update"
    if operation in {"apt_install", "apt_remove", "apt_search", "dpkg"}:
        package_name = _quote_value(package, "package name")
        return {
            "apt_install": f"sudo apt-get install -y {package_name}",
            "apt_remove": f"sudo apt-get remove -y {package_name}",
            "apt_search": f"apt-cache search {package_name}",
            "dpkg": f"dpkg -s {package_name}",
        }[operation]
    if operation in {"chmod", "chown", "chgrp"}:
        value = {"chmod": mode, "chown": owner, "chgrp": group}[operation]
        return f"sudo {operation} {_quote_value(value, 'permission or owner value')} {_quote_path(path)}"
    if operation == "ps":
        return "ps -eo pid,ppid,user,stat,%cpu,%mem,comm --sort=-%cpu"
    if operation == "top":
        return "top -b -n 1"
    if operation == "htop":
        return "htop -b -n 1"
    if operation == "disk_usage":
        return "df -hP"
    if operation == "kill":
        if not str(pid or "").isdigit():
            raise ValueError("The process ID must contain only digits.")
        return f"kill -{_quote_value(signal, 'signal')} {pid}"
    if operation in {"systemctl", "service"}:
        if action not in {"status", "start", "stop", "restart", "enable", "disable"}:
            raise ValueError("Service action must be status, start, stop, restart, enable, or disable.")
        return f"{operation} {_quote_value(action, 'service action')} {_quote_value(service, 'service name')}"
    return None
