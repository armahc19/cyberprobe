"""Allowlisted local terminal operations with confirmation for mutations."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+@:/=-]*$")
MAX_OUTPUT = 12000

OPERATIONS = {
    "pwd": "Show the current directory.",
    "cd": "Explain how to change the shell's current directory.",
    "ls": "List files and folders.",
    "tree": "Show a directory tree.",
    "cat": "Read a text file.",
    "less": "Read a file with a pager.",
    "head": "Read the beginning of a text file.",
    "tail": "Read the end of a text file.",
    "find": "Search for files and folders by name.",
    "find_files": "Find files by pattern and list their paths.",
    "latest_file": "Find the newest matching file and report its size.",
    "largest_files": "Find the largest files under a directory and report their sizes.",
    "grep": "Search text in a file.",
    "locate": "Search the system file index.",
    "which": "Find an executable in PATH.",
    "whereis": "Locate a command and related files.",
    "stat": "Show file metadata and permissions.",
    "mkdir": "Create a directory.",
    "touch": "Create an empty file.",
    "cp": "Copy a file or directory.",
    "mv": "Move or rename a file or directory.",
    "move_matching_files": "Move matching files into a directory.",
    "rm": "Delete a file or directory.",
    "rmdir": "Remove an empty directory.",
    "write_file": "Create or replace a text file with supplied content.",
    "nano": "Open a text file in the Nano editor.",
    "apt_update": "Refresh package indexes.",
    "apt_install": "Install a package.",
    "apt_remove": "Remove a package.",
    "apt_search": "Search available packages.",
    "dpkg": "Show installed package information.",
    "chmod": "Change file permissions.",
    "chown": "Change file ownership.",
    "chgrp": "Change file group ownership.",
    "ps": "List running processes.",
    "top": "Show a one-shot process and resource snapshot.",
    "htop": "Show a one-shot interactive-process snapshot.",
    "kill": "Send a signal to a process.",
    "systemctl": "Inspect or manage a systemd service.",
    "service": "Inspect or manage a service.",
    "disk_usage": "Report free space and filesystem usage.",
}

MUTATING = {"mkdir", "touch", "cp", "mv", "move_matching_files", "rm", "rmdir", "write_file", "apt_update", "apt_install", "apt_remove", "chmod", "chown", "chgrp", "kill"}


def authorization_enabled() -> bool:
    return os.environ.get("CYBERPROBE_AUTH", "0") == "1"


def _value(value: str | None, label: str) -> str:
    if not value or "\x00" in value or len(value) > 4096 or value.startswith("-"):
        raise ValueError(f"A valid {label} is required.")
    return value


def _name(value: str | None, label: str = "name") -> str:
    value = _value(value, label)
    if not SAFE_NAME.fullmatch(value):
        raise ValueError(f"Invalid {label}: use a simple package, command, or identifier.")
    return value


def _path(value: str | None, label: str = "path") -> str:
    value = _value(value, label)
    return os.path.abspath(os.path.expanduser(value))


def _run(command: list[str], timeout: int = 120) -> dict:
    if shutil.which(command[0]) is None:
        return {"command": shlex.join(command), "returncode": 127, "stdout": "", "stderr": f"Required tool not installed: {command[0]}"}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        return {"command": shlex.join(command), "returncode": -1, "stdout": error.stdout or "", "stderr": error.stderr or "Command timed out.", "timed_out": True}
    return {"command": shlex.join(command), "returncode": result.returncode, "stdout": result.stdout[:MAX_OUTPUT], "stderr": result.stderr[:3000], "timed_out": False}


def run_terminal_operation(operation: str, *, path: str | None = None, destination: str | None = None, pattern: str | None = None, content: str | None = None, package: str | None = None, mode: str | None = None, owner: str | None = None, group: str | None = None, pid: str | None = None, signal: str | None = None, service: str | None = None, action: str | None = None) -> dict:
    if operation not in OPERATIONS:
        raise ValueError(f"Unknown terminal operation. Choose from: {', '.join(OPERATIONS)}")

    target = path
    if operation == "pwd":
        return {"operation": operation, "command": "pwd", **_run(["pwd"])}
    if operation == "cd":
        directory = _path(target, "directory path")
        if not os.path.isdir(directory):
            raise ValueError(f"Directory not found: {directory}")
        return {"operation": operation, "command": f"cd {shlex.quote(directory)}", "returncode": 0, "stdout": f"The shell can change directory with: cd {shlex.quote(directory)}", "stderr": ""}
    if operation == "ls":
        return {"operation": operation, **_run(["ls", "-la", "--", _path(target or ".")])}
    if operation == "tree":
        return {"operation": operation, **_run(["tree", "-L", "2", _path(target or ".")])}
    if operation in {"cat", "less", "head", "tail", "stat"}:
        file_path = _path(target, "file path")
        command = {"cat": ["cat", "--", file_path], "less": ["less", "-X", "-F", "--", file_path], "head": ["head", "-n", "50", "--", file_path], "tail": ["tail", "-n", "50", "--", file_path], "stat": ["stat", "--", file_path]}[operation]
        return {"operation": operation, **_run(command)}
    if operation == "find":
        return {"operation": operation, **_run(["find", _path(target or "."), "-maxdepth", "3", "-iname", _value(pattern or "*", "search pattern")])}
    if operation in {"find_files", "latest_file", "largest_files"}:
        root = Path(_path(target or "."))
        search_pattern = _value(pattern or "*", "search pattern")
        if not root.is_dir():
            return {"operation": operation, "command": f"find {root}", "returncode": 1, "stdout": "", "stderr": f"Directory not found: {root}"}
        matches = sorted(
            (item for item in root.rglob(search_pattern) if item.is_file()),
            key=lambda item: str(item),
        )[:500]
        if operation == "largest_files":
            matches.sort(key=lambda item: item.stat().st_size, reverse=True)
            limit = max(1, min(int(destination or "5"), 50))
            output = "\n".join(f"{item}\t{item.stat().st_size} bytes" for item in matches[:limit])
            return {"operation": operation, "command": f"find {root} -type f", "returncode": 0, "stdout": output or "No files found.", "stderr": ""}
        if operation == "latest_file":
            matches.sort(key=lambda item: item.stat().st_mtime, reverse=True)
            if not matches:
                return {"operation": operation, "command": f"find {root} -iname {search_pattern}", "returncode": 0, "stdout": "No matching files found.", "stderr": ""}
            newest = matches[0]
            return {"operation": operation, "command": f"find {root} -iname {search_pattern}", "returncode": 0, "stdout": f"{newest}\t{newest.stat().st_size} bytes", "stderr": ""}
        return {"operation": operation, "command": f"find {root} -iname {search_pattern}", "returncode": 0, "stdout": "\n".join(str(item) for item in matches) or "No matching files found.", "stderr": ""}
    if operation == "grep":
        return {"operation": operation, **_run(["grep", "-n", "-I", "--", _value(pattern, "search text"), _path(target, "file path")])}
    if operation == "locate":
        return {"operation": operation, **_run(["locate", "-i", "--", _value(pattern, "search pattern")])}
    if operation in {"which", "whereis"}:
        return {"operation": operation, **_run([operation, _name(pattern or package, "command name")])}
    if operation in {"mkdir", "touch"}:
        command = [operation, "-p", _path(target, "path")] if operation == "mkdir" else [operation, _path(target, "file path")]
    elif operation in {"cp", "mv"}:
        command = [operation, "-r", _path(target, "source path"), _path(destination, "destination path")]
    elif operation == "move_matching_files":
        source = Path(_path(target, "source directory"))
        target_directory = Path(_path(destination, "destination directory"))
        search_pattern = _value(pattern or "*", "search pattern")
        files = [item for item in source.glob(search_pattern) if item.is_file()]
        display = f"move {search_pattern} from {source} to {target_directory} ({len(files)} matching files)"
        if not source.is_dir():
            return {"operation": operation, "command": display, "returncode": 1, "stdout": "", "stderr": f"Source directory not found: {source}"}
        if not target_directory.is_dir():
            return {"operation": operation, "command": display, "returncode": 1, "stdout": "", "stderr": f"Destination directory not found: {target_directory}"}
        if not authorization_enabled():
            return {"operation": operation, "command": display, "returncode": 4, "stdout": "", "stderr": "Authorization is OFF. Run 'auth on' before allowing terminal changes.", "authorization_required": True}
        for item in files:
            shutil.move(str(item), str(target_directory / item.name))
        return {"operation": operation, "command": display, "returncode": 0, "stdout": f"Moved {len(files)} file(s) to {target_directory}.", "stderr": ""}
    elif operation in {"rm", "rmdir"}:
        command = [operation, "-r", _path(target, "path")] if operation == "rm" else [operation, _path(target, "directory path")]
    elif operation == "write_file":
        command = ["tee", _path(target, "file path")]
    elif operation == "nano":
        command = ["nano", _path(target, "file path")]
    elif operation == "apt_update":
        command = ["sudo", "apt-get", "update"]
    elif operation in {"apt_install", "apt_remove", "apt_search", "dpkg"}:
        package_name = _name(package, "package name")
        command = {"apt_install": ["sudo", "apt-get", "install", "-y", package_name], "apt_remove": ["sudo", "apt-get", "remove", "-y", package_name], "apt_search": ["apt-cache", "search", package_name], "dpkg": ["dpkg", "-s", package_name]}[operation]
    elif operation in {"chmod", "chown", "chgrp"}:
        value = _name(mode if operation == "chmod" else owner if operation == "chown" else group, "permission or owner value")
        command = ["sudo", operation, value, _path(target, "path")]
    elif operation == "ps":
        command = ["ps", "-eo", "pid,ppid,user,stat,%cpu,%mem,comm", "--sort=-%cpu"]
    elif operation in {"top", "htop"}:
        if operation == "htop":
            command = ["htop", "-b", "-n", "1"]
        else:
            command = ["top", "-b", "-n", "1"]
    elif operation == "disk_usage":
        command = ["df", "-hP"]
    elif operation == "kill":
        process_id = _name(pid, "process ID")
        if not process_id.isdigit():
            raise ValueError("The process ID must contain only digits.")
        command = ["kill", "-" + _name(signal or "TERM", "signal"), process_id]
    elif operation in {"systemctl", "service"}:
        service_name = _name(service, "service name")
        selected_action = _name(action or "status", "service action")
        if selected_action not in {"status", "start", "stop", "restart", "enable", "disable"}:
            raise ValueError("Service action must be status, start, stop, restart, enable, or disable.")
        command = [operation, selected_action, service_name]
    else:
        raise ValueError("This operation is not implemented.")

    display = shlex.join(command)
    if operation == "write_file":
        if content is None:
            raise ValueError("Content is required when writing a file.")
        display = f"tee {shlex.quote(_path(target, 'file path'))}"
    requires_confirmation = operation in MUTATING or (
        operation in {"systemctl", "service"} and (action or "status") != "status"
    )
    if requires_confirmation and not authorization_enabled():
        return {
            "operation": operation,
            "command": display,
            "returncode": 4,
            "stdout": "",
            "stderr": "Authorization is OFF. Run 'auth on' before allowing terminal changes.",
            "authorization_required": True,
        }
    if operation == "write_file":
        result = subprocess.run(command, input=content, capture_output=True, text=True, timeout=120)
        return {"operation": operation, "command": display, "returncode": result.returncode, "stdout": result.stdout[:MAX_OUTPUT], "stderr": result.stderr[:3000]}
    return {"operation": operation, **_run(command)}
