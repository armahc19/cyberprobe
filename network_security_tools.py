"""Read-only network posture checks for the local Linux host."""
import shutil
import subprocess

ALLOWED_CHECKS = {
    "interfaces": (["ip", "-brief", "addr"], "List network interfaces and addresses."),
    "network_discovery": (["ip", "neigh"], "Show locally known network neighbors."),
    "listening_ports": (["ss", "-tulpen"], "Show listening TCP and UDP sockets."),
    "routing": (["ip", "route", "show"], "Show the routing table."),
    "dns": (["resolvectl", "status"], "Show DNS resolver configuration."),
    "firewall_ufw": (["ufw", "status", "verbose"], "Inspect UFW firewall status."),
    "firewall_nftables": (["nft", "list", "ruleset"], "Inspect nftables firewall rules."),
    "packet_summary": (["tcpdump", "-nn", "-c", "25"], "Capture a short packet sample."),
}

def run_check(check_type: str):
    if check_type not in ALLOWED_CHECKS:
        raise ValueError(f"Unknown network check: {check_type}")
    command = ALLOWED_CHECKS[check_type][0]
    if shutil.which(command[0]) is None:
        return {"check_type": check_type, "command": " ".join(command), "returncode": 127, "stdout": "", "stderr": f"Required tool not installed: {command[0]}", "timed_out": False}
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=45)
        return {"check_type": check_type, "command": " ".join(command), "returncode": proc.returncode, "stdout": proc.stdout[:10000], "stderr": proc.stderr[:3000], "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"check_type": check_type, "command": " ".join(command), "returncode": -1, "stdout": exc.stdout or "", "stderr": exc.stderr or "", "timed_out": True}
