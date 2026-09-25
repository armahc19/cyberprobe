"""
security_tools.py

Handles everything that touches the actual system:
- validating scan targets (format and injection checks only)
- running nmap with a strict, predefined allowlist of scan types
- capturing output safely (timeouts, no shell injection, no raw command strings)

The LLM agent NEVER constructs a raw nmap command. It only ever picks a
scan_type from ALLOWED_SCANS below. This file is the only place that
actually calls subprocess.
"""

import ipaddress
import re
import subprocess
import shutil

# ---------------------------------------------------------------------------
# 1. Allowlisted scan types
#    Each entry maps a scan_type name -> fixed nmap flags.
#    The agent picks a NAME, never raw flags. This is the core safety control.
# ---------------------------------------------------------------------------

ALLOWED_SCANS = {
    "quick_scan": {
        "flags": ["-F"],
        "needs_root": False,
        "description": "Fast scan of the 100 most common ports.",
        "typical_seconds": 15,
    },
    "version_scan": {
        "flags": ["-sV"],
        "needs_root": False,
        "description": "Detects service names and version numbers on open ports.",
        "typical_seconds": 60,
    },
    "full_port_scan": {
        "flags": ["-p-"],
        "needs_root": False,
        "description": "Scans all 65535 ports. Slower but thorough.",
        "typical_seconds": 300,
    },
    "os_detection": {
        "flags": ["-O"],
        "needs_root": True,
        "description": "Attempts to guess the target's operating system.",
        "typical_seconds": 30,
    },
}

# Hard cap so a scan can never hang forever regardless of type
MAX_TIMEOUT_SECONDS = 600

# Broader reconnaissance capabilities. Commands and flags are fixed here;
# the model selects a capability name and never supplies a shell command.
RECON_CAPABILITIES = {
    "host_discovery_nmap": (["nmap", "-sn"], "Nmap host discovery."),
    "host_discovery_arp_scan": (["arp-scan", "--localnet"], "ARP-based local host discovery."),
    "host_discovery_fping": (["fping", "-a", "-q"], "Check whether the supplied host responds to ICMP."),
    "resolve_ip_python": (["python3", "-c", "import socket,sys; print(socket.gethostbyname(sys.argv[1]))"], "Resolve a hostname to an IP address."),
    "resolve_ip_getent": (["getent", "hosts"], "Resolve a hostname using the system resolver."),
    "dns_records_dig": (["dig"], "Query DNS records."),
    "dns_records_host": (["host"], "Query DNS records with host."),
    "dns_records_nslookup": (["nslookup"], "Query DNS records with nslookup."),
    "common_ports_nmap": (["nmap", "-F"], "Scan common TCP ports."),
    "full_tcp_nmap": (["nmap", "-p-"], "Scan all TCP ports."),
    "common_ports_masscan": (["masscan", "--top-ports", "100", "--rate", "1000"], "Fast scan of common TCP ports."),
    "common_ports_naabu": (["naabu", "-top-ports", "100", "-silent"], "Scan common TCP ports with Naabu."),
    "selected_ports_nmap": (["nmap", "-p"], "Scan a caller-selected port list."),
    "service_version_nmap": (["nmap", "-sV"], "Identify services and versions."),
    "service_identification_httpx": (["httpx", "-silent", "-status-code", "-title", "-tech-detect"], "Identify live HTTP services and technologies."),
    "banner_nmap": (["nmap", "-sV", "--script", "banner"], "Collect service banners with nmap."),
    "banner_netcat": (["nc", "-vz", "-w", "3"], "Attempt a TCP banner connection."),
    "os_detection_nmap": (["nmap", "-O"], "Estimate the target operating system."),
    "reverse_dns_dig": (["dig", "-x"], "Perform reverse DNS lookup."),
    "reverse_dns_host": (["host"], "Perform reverse DNS lookup with host."),
    "http_headers_curl": (["curl", "-I", "--max-time", "10"], "Fetch HTTP response headers."),
    "http_methods_curl": (["curl", "-X", "OPTIONS", "-i", "--max-time", "10"], "Check advertised HTTP methods."),
    "web_technologies_whatweb": (["whatweb"], "Identify technologies exposed by a web target."),
    "web_technologies_nmap": (["nmap", "-sV", "--script", "http-title,http-server-header"], "Identify basic web technologies."),
    "web_resources_curl": (["curl", "-L", "--max-time", "10"], "Fetch a web resource for inspection."),
    "ssh_enum_nmap": (["nmap", "-sV", "--script", "ssh2-enum-algos"], "Enumerate SSH service details."),
    "ftp_enum_nmap": (["nmap", "-sV", "--script", "ftp-anon"], "Inspect FTP service exposure."),
    "smb_enum_nmap": (["nmap", "-sV", "--script", "smb-os-discovery"], "Inspect SMB service details."),
    "smb_enum_client": (["smbclient", "-L"], "List SMB shares when permitted."),
    "smb_enum_enum4linux": (["enum4linux-ng", "-A"], "Enumerate permitted SMB and Windows service details."),
    "dns_enumeration": (["dnsrecon", "-d"], "Enumerate DNS records for a domain."),
    "http_enum_nmap": (["nmap", "-sV", "--script", "http-title,http-methods"], "Enumerate HTTP service details."),
    "web_vulnerability_nikto": (["nikto", "-host"], "Run Nikto's non-destructive web server checks."),
    "vulnerability_nmap_nse": (["nmap", "--script", "vuln"], "Run Nmap's vulnerability NSE scripts."),
}


# ---------------------------------------------------------------------------
# 2. Target validation
#    Reject malformed targets and shell metacharacters. Any IP or hostname
#    the user supplies is accepted; they are responsible for authorization.
# ---------------------------------------------------------------------------

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")


class TargetValidationError(Exception):
    pass


def validate_target(target: str) -> str:
    """
    Returns the cleaned target string if allowed, otherwise raises
    TargetValidationError with a human-readable reason.
    """
    target = target.strip()

    if not target:
        raise TargetValidationError("No target was provided.")

    # Reject anything that looks like shell metacharacters, flags, etc.
    # (defense in depth -- we never build a shell string, but reject early anyway)
    if any(ch in target for ch in [";", "|", "&", "$", "`", ">", "<", " "]):
        raise TargetValidationError(
            "Target contains characters that aren't allowed. "
            "Enter a plain IP address or hostname."
        )

    # Try as an IP address first
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass  # not a raw IP, fall through to hostname handling

    if not HOSTNAME_RE.match(target):
        raise TargetValidationError(f"'{target}' doesn't look like a valid hostname or IP.")

    return target


# ---------------------------------------------------------------------------
# 3. Running nmap
# ---------------------------------------------------------------------------

class ScanResult:
    def __init__(self, scan_type, target, command, returncode, stdout, stderr, timed_out=False):
        self.scan_type = scan_type
        self.target = target
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def success(self):
        return self.returncode == 0 and not self.timed_out


def confirm_and_maybe_sudo(scan_type: str) -> bool:
    """
    If the scan needs root, ask the user yes/no in the terminal.
    We never capture or handle the password ourselves -- if they say yes,
    we call `sudo nmap ...` and let sudo prompt for the password directly.
    Returns True if it's OK to proceed, False if the user declined.
    """
    spec = ALLOWED_SCANS[scan_type]
    if not spec["needs_root"]:
        return True

    answer = input(
        f"\n'{scan_type}' requires administrator (root) privileges to run. "
        f"Allow it to run with sudo? (yes/no): "
    ).strip().lower()

    return answer in ("y", "yes")


def run_scan(scan_type: str, target: str) -> ScanResult:
    """
    Runs an allowlisted nmap scan against a validated target.
    Raises ValueError if scan_type isn't in the allowlist.
    Raises TargetValidationError if the target fails validation.
    """
    if scan_type not in ALLOWED_SCANS:
        raise ValueError(
            f"'{scan_type}' is not an allowed scan type. "
            f"Choose one of: {', '.join(ALLOWED_SCANS.keys())}"
        )

    clean_target = validate_target(target)
    spec = ALLOWED_SCANS[scan_type]

    command = ["nmap"] + spec["flags"] + [clean_target]
    if spec["needs_root"]:
        command = ["sudo"] + command

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=MAX_TIMEOUT_SECONDS,
        )
        return ScanResult(
            scan_type=scan_type,
            target=clean_target,
            command=" ".join(command),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as e:
        return ScanResult(
            scan_type=scan_type,
            target=clean_target,
            command=" ".join(command),
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
            timed_out=True,
        )


def run_recon_capability(capability: str, target: str, ports: str | None = None) -> ScanResult:
    """Run one fixed recon capability against a validated target."""
    if capability not in RECON_CAPABILITIES:
        raise ValueError(f"'{capability}' is not an allowed recon capability.")
    clean_target = validate_target(target)
    command = list(RECON_CAPABILITIES[capability][0])
    if capability == "selected_ports_nmap":
        if not ports or not re.fullmatch(r"[0-9,-]+", ports):
            raise ValueError("Selected ports must contain only numbers, commas, and hyphens.")
        command.append(ports)
    if capability == "resolve_ip_python":
        command.append(clean_target)
    elif capability == "reverse_dns_dig":
        command.append(clean_target)
    elif capability == "selected_ports_nmap":
        command.append(clean_target)
    elif capability == "host_discovery_arp_scan":
        # arp-scan discovers the local link by itself; it does not take a host.
        pass
    else:
        command.append(clean_target)
    if shutil.which(command[0]) is None:
        return ScanResult(capability, clean_target, " ".join(command), 127, "", f"Required tool not installed: {command[0]}")
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=MAX_TIMEOUT_SECONDS)
        return ScanResult(capability, clean_target, " ".join(command), proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        return ScanResult(capability, clean_target, " ".join(command), -1, e.stdout or "", e.stderr or "", True)
