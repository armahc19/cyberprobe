"""Approval-gated installation of CyberProbe's allowlisted dependencies."""

from __future__ import annotations

import shutil
import subprocess


INSTALLABLE_TOOLS = {
    "nmap": "nmap",
    "arp-scan": "arp-scan",
    "curl": "curl",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "subfinder": "subfinder",
    "whatweb": "whatweb",
    "dig": "dnsutils",
    "host": "dnsutils",
    "nslookup": "dnsutils",
    "nc": "netcat-openbsd",
    "nuclei": "nuclei",
    "lynis": "lynis",
    "ufw": "ufw",
    "nft": "nftables",
    "tcpdump": "tcpdump",
    "auditctl": "auditd",
    "systemctl": "systemd",
    "ss": "iproute2",
    "sha256sum": "coreutils",
    "stat": "coreutils",
    "vol": "volatility3",
    "mmls": "sleuthkit",
    "fsstat": "sleuthkit",
    "fls": "sleuthkit",
    "tsk_recover": "sleuthkit",
    "foremost": "foremost",
}


def _package_manager() -> tuple[str, str] | None:
    managers = (
        ("apt-get", "apt"),
        ("dnf", "dnf"),
        ("pacman", "pacman"),
    )
    for binary, name in managers:
        if shutil.which(binary):
            return binary, name
    return None


def _command(tool: str) -> tuple[list[str], str]:
    if tool not in INSTALLABLE_TOOLS:
        known = ", ".join(sorted(INSTALLABLE_TOOLS))
        raise ValueError(f"'{tool}' is not an installable CyberProbe tool. Choose from: {known}")

    manager = _package_manager()
    if manager is None:
        raise RuntimeError("No supported package manager found. Supported managers: apt, dnf, pacman.")

    binary, name = manager
    package = INSTALLABLE_TOOLS[tool]
    if name == "apt":
        return ["sudo", binary, "install", "-y", package], f"sudo {binary} install -y {package}"
    if name == "dnf":
        return ["sudo", binary, "install", "-y", package], f"sudo {binary} install -y {package}"
    return ["sudo", binary, "-S", "--noconfirm", package], f"sudo {binary} -S --noconfirm {package}"


def install_tool(tool: str) -> dict:
    """Install one allowlisted tool after an interactive confirmation."""
    tool = tool.strip()
    if shutil.which(tool):
        return {"tool": tool, "installed": True, "message": f"{tool} is already installed."}

    command, display_command = _command(tool)
    answer = input(
        f"'{tool}' is missing. CyberProbe can run '{display_command}'. Continue? (yes/no): "
    ).strip().lower()
    if answer not in {"y", "yes"}:
        return {"tool": tool, "installed": False, "declined": True, "message": "Installation cancelled."}

    result = subprocess.run(command, text=True, timeout=900)
    installed = result.returncode == 0 and shutil.which(tool) is not None
    message = (
        f"Installed {tool}."
        if installed
        else f"The package manager exited with code {result.returncode}; {tool} is still unavailable."
    )
    return {"tool": tool, "installed": installed, "returncode": result.returncode, "message": message}
