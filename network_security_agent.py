"""Specialist agent for defensive network posture analysis."""
import json
from finding_model import finding_schema
from llm_config import MODEL
from network_security_tools import ALLOWED_CHECKS, run_check

SYSTEM_PROMPT = """You are CyberProbe's Network Security Agent. Analyze Linux network posture with approved, read-only checks. Explain interfaces, discovery, listening ports, insecure protocols, firewall exposure, routes, DNS, packet samples, traffic investigation, and anomalies when evidence supports them. Distinguish facts from hypotheses. Never exploit services, change firewall rules, kill traffic, or run raw commands. Packet capture is short and may require administrator permission; report permission errors.\n\n""" + "\n".join(f"- {n}: {s[1]}" for n, s in ALLOWED_CHECKS.items())

TOOLS = [{"type": "function", "function": {"name": "run_network_check", "description": "Run one approved read-only local network posture check.", "parameters": {"type": "object", "properties": {"check_type": {"type": "string", "enum": list(ALLOWED_CHECKS)}}, "required": ["check_type"]}}}]

class NetworkSecurityAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
        reply = response.choices[0].message
        log = {"agent": "network_security", "tool_type": None, "command": None, "returncode": None, "stdout": None, "stderr": None, "timed_out": False}
        while reply.tool_calls:
            self.messages.append(reply)
            for call in reply.tool_calls:
                args = json.loads(call.function.arguments or "{}")
                payload = run_check(args.get("check_type"))
                log.update({"tool_type": payload.get("check_type"), "command": payload.get("command"), "returncode": payload.get("returncode"), "stdout": payload.get("stdout"), "stderr": payload.get("stderr"), "timed_out": payload.get("timed_out", False)})
                self.messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(payload)})
            response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
            reply = response.choices[0].message
        self.messages.append(reply)
        return reply.content or "The network security checks finished, but the model returned no summary.", log
