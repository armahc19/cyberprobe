"""
linux_tools.py

Linux system inspection domain.
Mirrors the pattern in security_tools.py:
- a fixed allowlist of tools/flags (the agent picks a NAME, never raw commands)
- safe subprocess execution with timeouts

This file is the only place that runs Linux inspection commands.
"""

from __future__ import annotations

import subprocess

ALLOWED_TOOLS = {
    "system_info": {
        "binary": "uname",
        "flags": ["-a"],
        "description": "Shows the OS kernel, architecture, and basic system identity.",
    },
    "host_identity": {
        "binary": "hostnamectl",
        "flags": [],
        "description": "Shows host and operating system details.",
    },
    "distribution_info": {
        "binary": "lsb_release",
        "flags": ["-a"],
        "description": "Shows Linux distribution name and version.",
    },
    "cpu_info": {
        "binary": "lscpu",
        "flags": [],
        "description": "Shows CPU architecture, cores, and processor details.",
    },
    "memory_info": {
        "binary": "lsmem",
        "flags": [],
        "description": "Shows installed memory layout and DIMM information.",
    },
    "block_devices": {
        "binary": "lsblk",
        "flags": [],
        "description": "Shows disks, partitions, and mount points.",
    },
    "process_list": {
        "binary": "ps",
        "flags": ["-eo", "pid,ppid,user,stat,%cpu,%mem,comm", "--sort=-%cpu"],
        "description": "Lists running processes sorted by CPU usage.",
    },
    "top_snapshot": {
        "binary": "top",
        "flags": ["-b", "-n", "1"],
        "description": "Captures a single top-style snapshot of live resource usage.",
    },
    "process_lookup": {
        "binary": "pgrep",
        "flags": ["-a"],
        "description": "Finds processes by name and shows their command lines.",
    },
    "process_id_lookup": {
        "binary": "pidof",
        "flags": [],
        "description": "Finds the process ID for a named program.",
    },
    "service_status": {
        "binary": "systemctl",
        "flags": ["--no-pager", "status"],
        "description": "Shows the status of a systemd service.",
    },
    "failed_services": {
        "binary": "systemctl",
        "flags": ["--no-pager", "--failed"],
        "description": "Lists systemd services that have failed.",
    },
    "disk_usage": {
        "binary": "df",
        "flags": ["-h"],
        "description": "Shows mounted filesystems and how full they are.",
    },
    "directory_usage": {
        "binary": "du",
        "flags": ["-sh"],
        "description": "Summarizes how much disk space a directory uses.",
    },
    "block_ids": {
        "binary": "blkid",
        "flags": [],
        "description": "Shows filesystem UUIDs and labels for block devices.",
    },
    "mount_points": {
        "binary": "findmnt",
        "flags": [],
        "description": "Shows mounted filesystems and where they are mounted.",
    },
    "current_user": {
        "binary": "id",
        "flags": [],
        "description": "Shows the current user ID and groups.",
    },
    "logged_in_users": {
        "binary": "who",
        "flags": [],
        "description": "Shows users currently logged in.",
    },
    "active_sessions": {
        "binary": "w",
        "flags": [],
        "description": "Shows who is logged in and what they are doing.",
    },
    "recent_logins": {
        "binary": "last",
        "flags": ["-n", "10"],
        "description": "Shows recent login history.",
    },
    "user_lookup": {
        "binary": "getent",
        "flags": ["passwd"],
        "description": "Looks up account information from system databases.",
    },
    "group_lookup": {
        "binary": "groups",
        "flags": [],
        "description": "Shows the groups for a user.",
    },
    "file_listing": {
        "binary": "ls",
        "flags": ["-la"],
        "description": "Lists files with permissions and ownership.",
    },
    "file_stat": {
        "binary": "stat",
        "flags": [],
        "description": "Shows detailed file metadata such as mode, owner, and timestamps.",
    },
    "path_resolution": {
        "binary": "namei",
        "flags": [],
        "description": "Shows each directory component in a path and its permissions.",
    },
    "acl_lookup": {
        "binary": "getfacl",
        "flags": [],
        "description": "Shows POSIX ACL permissions for a file or directory.",
    },
    "network_interfaces": {
        "binary": "ip",
        "flags": ["addr"],
        "description": "Shows network interfaces and assigned IP addresses.",
    },
    "network_links": {
        "binary": "ip",
        "flags": ["link"],
        "description": "Shows network link status for interfaces.",
    },
    "routing_table": {
        "binary": "ip",
        "flags": ["route"],
        "description": "Shows the system routing table.",
    },
    "socket_listeners": {
        "binary": "ss",
        "flags": ["-tulpn"],
        "description": "Shows listening sockets and the programs using them.",
    },
    "dns_status": {
        "binary": "resolvectl",
        "flags": ["status"],
        "description": "Shows DNS resolver configuration and status.",
    },
    "connectivity_check": {
        "binary": "ping",
        "flags": ["-c", "4"],
        "description": "Checks basic network reachability with a short ping test.",
    },
    "system_journal": {
        "binary": "journalctl",
        "flags": ["-n", "50", "--no-pager"],
        "description": "Shows recent system log messages from the journal.",
    },
    "kernel_messages": {
        "binary": "dmesg",
        "flags": ["--ctime", "--nopager"],
        "description": "Shows kernel messages from the boot and runtime log buffer.",
    },
    "uptime": {
        "binary": "uptime",
        "flags": [],
        "description": "Shows how long the system has been running and load average.",
    },
    "memory_usage": {
        "binary": "free",
        "flags": ["-h"],
        "description": "Shows memory usage in a human-readable format.",
    },
    "virtual_memory": {
        "binary": "vmstat",
        "flags": ["1", "5"],
        "description": "Shows CPU, memory, and I/O activity over a short interval.",
    },
    "disk_io": {
        "binary": "iostat",
        "flags": ["-xz", "1", "3"],
        "description": "Shows disk and CPU I/O activity over a short interval.",
    },
}

MAX_TIMEOUT_SECONDS = 120


class LinuxResult:
    def __init__(self, tool_type, command, returncode, stdout, stderr, timed_out=False):
        self.tool_type = tool_type
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out


def _is_tool_installed(binary: str) -> bool:
    from shutil import which

    return which(binary) is not None


def run_tool(tool_type: str, target: str | None = None) -> LinuxResult:
    if tool_type not in ALLOWED_TOOLS:
        raise ValueError(
            f"'{tool_type}' is not an allowed Linux tool. "
            f"Choose one of: {', '.join(ALLOWED_TOOLS.keys())}"
        )

    spec = ALLOWED_TOOLS[tool_type]
    binary = spec["binary"]

    if not _is_tool_installed(binary):
        return LinuxResult(
            tool_type=tool_type,
            command=f"{binary} (not installed)",
            returncode=-1,
            stdout="",
            stderr=f"'{binary}' is not installed on this system.",
        )

    command = [binary] + spec["flags"]
    if target:
        command.append(target)

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=MAX_TIMEOUT_SECONDS,
        )
        return LinuxResult(
            tool_type=tool_type,
            command=" ".join(command),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as e:
        return LinuxResult(
            tool_type=tool_type,
            command=" ".join(command),
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
            timed_out=True,
        )
