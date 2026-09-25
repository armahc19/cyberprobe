"""Tool adapters: capabilities in, normalized evidence out.

Adapters keep tool-specific command construction and parsing out of agents.
Agents select a capability; they never provide arbitrary command arguments.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from security_tools import validate_target
from .parsers import PARSERS


def _web_target(value: str) -> str:
    """Validate a URL without allowing shell/control characters."""
    value = (value or "").strip()
    if any(ch in value for ch in "\r\n;|&$`'\" "):
        raise ValueError("A URL without shell or whitespace characters is required.")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an HTTP or HTTPS URL.")
    validate_target(parsed.hostname)
    return value


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version: str
    tool_type: str
    capabilities: tuple[str, ...]
    inputs: dict[str, dict]
    outputs: tuple[str, ...]
    timeout: int = 600
    install_hint: str | None = None


@dataclass(frozen=True)
class ToolInstallation:
    name: str
    installed: bool
    executable: str | None = None
    version: str | None = None
    error: str | None = None
    install_hint: str | None = None


@dataclass
class ToolResult:
    tool: str
    capability: str
    target: str | None
    command: str
    status: str
    observations: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    evidence: str = ""
    error: str | None = None
    timed_out: bool = False

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class ToolAdapter:
    def __init__(self, spec: ToolSpec, builder: Callable[[str, dict], list[str]], parser: Callable[[str, str], dict] | None = None):
        self.spec = spec
        self._builder = builder
        self._parser = parser or self._default_parser

    def available(self) -> bool:
        return shutil.which(self.spec.name) is not None

    def installation(self) -> ToolInstallation:
        executable = shutil.which(self.spec.name)
        if not executable:
            return ToolInstallation(self.spec.name, False, install_hint=self.spec.install_hint)
        try:
            probe = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=10)
            output = (probe.stdout or probe.stderr).strip().splitlines()
            return ToolInstallation(self.spec.name, True, executable, output[0][:300] if output else None, install_hint=self.spec.install_hint)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return ToolInstallation(self.spec.name, True, executable, error=str(exc), install_hint=self.spec.install_hint)

    def command(self, capability: str, inputs: dict) -> list[str]:
        if capability not in self.spec.capabilities:
            raise ValueError(f"{self.spec.name} does not support '{capability}'.")
        target = inputs.get("target")
        if self.spec.inputs.get("target", {}).get("required"):
            if not target:
                raise ValueError("A target is required.")
            inputs = dict(inputs)
            inputs["target"] = self._validate_target(target)
        return self._builder(capability, inputs)

    def _validate_target(self, target: str) -> str:
        return _web_target(target) if self.spec.inputs.get("target", {}).get("format") == "url" else validate_target(target)

    def run(self, capability: str, inputs: dict) -> ToolResult:
        command = self.command(capability, inputs)
        target = inputs.get("target")
        display = " ".join(command)
        if not self.available():
            return ToolResult(self.spec.name, capability, target, display, "unavailable", error=f"Required tool not installed: {self.spec.name}")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=self.spec.timeout)
        except subprocess.TimeoutExpired as exc:
            return ToolResult(self.spec.name, capability, target, display, "timeout", evidence=(exc.stdout or ""), timed_out=True)
        parsed = self._parser(result.stdout, result.stderr)
        return ToolResult(self.spec.name, capability, target, display, "completed" if result.returncode == 0 else "failed", evidence=result.stdout[:12000], **parsed)

    @staticmethod
    def _default_parser(stdout: str, stderr: str) -> dict:
        return {"observations": [], "findings": [], "error": stderr[:3000] if stderr else None}


class ToolRegistry:
    def __init__(self):
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        if adapter.spec.name in self._adapters:
            raise ValueError(f"Tool already registered: {adapter.spec.name}")
        self._adapters[adapter.spec.name] = adapter

    def get(self, name: str) -> ToolAdapter:
        try:
            return self._adapters[name]
        except KeyError as exc:
            raise ValueError(f"Unknown tool: {name}") from exc

    def capabilities(self) -> list[dict]:
        return [{"tool": a.spec.name, "capabilities": list(a.spec.capabilities), "available": a.available()} for a in self._adapters.values()]

    def inventory(self) -> list[dict]:
        return [installation.__dict__.copy() for installation in (adapter.installation() for adapter in self._adapters.values())]

    def find(self, capability: str) -> list[ToolAdapter]:
        return [a for a in self._adapters.values() if capability in a.spec.capabilities]

    def run(self, tool: str, capability: str, inputs: dict) -> dict:
        return self.get(tool).run(capability, inputs).to_dict()


def _nmap_command(capability: str, inputs: dict) -> list[str]:
    modes = {
        "host_discovery": ["-sn"],
        "port_scanning": ["-F"],
        "service_detection": ["-sV"],
        "os_detection": ["-O"],
        "script_scanning": ["--script", "vuln"],
    }
    command = ["nmap"] + modes[capability]
    if inputs.get("ports"):
        if not str(inputs["ports"]).replace(",", "").replace("-", "").isdigit():
            raise ValueError("ports must contain only numbers, commas, and hyphens.")
        command += ["-p", str(inputs["ports"])]
    return command + ["-oX", "-", inputs["target"]]


def _fixed_command(binary: str, flags: list[str]) -> Callable[[str, dict], list[str]]:
    def builder(capability: str, inputs: dict) -> list[str]:
        # arp-scan's local discovery mode determines its own local network.
        if binary == "arp-scan" and "--localnet" in flags:
            return [binary, *flags]
        return [binary, *flags, inputs["target"]]
    return builder


def default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(ToolAdapter(ToolSpec(
        name="nmap", version="7.x", tool_type="cli",
        capabilities=("host_discovery", "port_scanning", "service_detection", "os_detection", "script_scanning"),
        inputs={"target": {"type": "target", "required": True}, "ports": {"type": "string", "required": False}},
        outputs=("hosts", "ports", "services", "os", "scripts")), _nmap_command))
    tools = [
        ("masscan", ("port_scanning",), ["--top-ports", "100", "--rate", "1000"], ("ports",)),
        ("rustscan", ("port_scanning",), ["--ulimit", "5000", "-a"], ("ports",)),
        ("arp-scan", ("host_discovery",), ["--localnet"], ("hosts",)),
        ("nuclei", ("vulnerability_detection", "technology_detection"), ["-silent"], ("findings", "technologies")),
        ("nikto", ("vulnerability_detection",), ["-host"], ("findings", "evidence")),
        ("httpx", ("web_service_detection", "technology_detection"), ["-silent", "-status-code", "-title", "-tech-detect"], ("services", "technologies")),
        ("whatweb", ("technology_detection",), ["--no-errors"], ("technologies",)),
        ("gobuster", ("web_content_discovery",), ["dir", "-q"], ("endpoints",)),
        ("ffuf", ("web_content_discovery",), ["-s"], ("endpoints",)),
    ]
    url_tools = {"nuclei", "nikto", "httpx", "whatweb", "gobuster", "ffuf"}
    for name, capabilities, flags, outputs in tools:
        registry.register(ToolAdapter(ToolSpec(
            name=name, version="system", tool_type="cli", capabilities=capabilities,
            inputs={"target": {"type": "target", "required": True, "format": "url" if name in url_tools else "host"}},
            outputs=outputs), _fixed_command(name, flags), PARSERS.get(name)))
    return registry
