"""Output parsers that normalize common security-tool formats."""
from __future__ import annotations
import json
import re
import xml.etree.ElementTree as ET

def _empty():
    return {"observations": [], "findings": [], "error": None}

def parse_nmap(stdout: str, stderr: str = "") -> dict:
    result = _empty()
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        result["error"] = (stderr or "Nmap did not return XML output.")[:3000]
        return result
    for host in root.findall("host"):
        address = host.find("address")
        asset = address.get("addr") if address is not None else None
        for port in host.findall(".//port"):
            state = port.find("state")
            service = port.find("service")
            item = {"asset": asset, "port": port.get("portid"), "protocol": port.get("protocol"), "state": state.get("state") if state is not None else None}
            if service is not None:
                item.update({"service": service.get("name"), "version": service.get("version"), "product": service.get("product")})
            result["observations"].append(item)
            for script in port.findall("script"):
                result["findings"].append({"title": script.get("id", "Nmap script result"), "affected_asset": f"{asset}:{port.get('portid')}", "evidence": [script.get("output", "")], "confidence": "medium"})
    return result

def parse_nuclei(stdout: str, stderr: str = "") -> dict:
    result = _empty()
    for line in stdout.splitlines():
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        info = item.get("info", {})
        result["findings"].append({"title": info.get("name") or item.get("template-id", "Nuclei finding"), "severity": info.get("severity", "informational"), "affected_asset": item.get("matched-at") or item.get("host"), "evidence": [item.get("matcher-name") or item.get("type", "nuclei")]})
    if not result["findings"] and stderr: result["error"] = stderr[:3000]
    return result

def parse_httpx(stdout: str, stderr: str = "") -> dict:
    return {"observations": [{"url": line.strip(), "raw": line.strip()} for line in stdout.splitlines() if line.strip()], "findings": [], "error": stderr[:3000] if stderr and not stdout else None}

def parse_line_discovery(stdout: str, stderr: str = "") -> dict:
    values = [{"value": line.strip()} for line in stdout.splitlines() if line.strip() and not line.startswith("#")]
    return {"observations": values, "findings": [], "error": stderr[:3000] if stderr and not values else None}

def parse_nikto(stdout: str, stderr: str = "") -> dict:
    result = parse_line_discovery(stdout, stderr)
    result["findings"] = [{"title": item["value"], "evidence": [item["value"]], "confidence": "medium"} for item in result["observations"] if item["value"].startswith("+")]
    return result

def parse_metasploit(stdout: str, stderr: str = "") -> dict:
    result = parse_line_discovery(stdout, stderr)
    result["findings"] = [{"title": "Metasploit result", "evidence": [item["value"]], "confidence": "medium"} for item in result["observations"] if re.search(r"session|meterpreter|vulnerable|excellent|great", item["value"], re.I)]
    return result

PARSERS = {"nmap": parse_nmap, "nuclei": parse_nuclei, "httpx": parse_httpx, "nikto": parse_nikto, "gobuster": parse_line_discovery, "ffuf": parse_line_discovery, "metasploit": parse_metasploit}
