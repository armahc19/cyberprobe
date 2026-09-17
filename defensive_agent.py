"""Specialist agent for defensive security monitoring and investigation."""

import json

from finding_model import finding_schema
from defensive_tools import ALLOWED_CHECKS, run_check, run_investigation_snapshot
from llm_config import MODEL


SYSTEM_PROMPT = """You are CyberProbe's Defensive Security Agent, a beginner-friendly
defensive monitoring and incident-investigation specialist.

You perform read-only checks on systems the user owns or is authorized to
monitor. Use only the approved defensive checks listed below. Explain findings
in plain language and distinguish observed evidence from hypotheses.

Your responsibilities include security monitoring, threat detection, threat
hunting, endpoint and service review, firewall posture review, IOC-oriented
file checks, evidence preservation, and defensive security posture assessment.

Never modify firewall rules, isolate hosts, kill processes, delete or quarantine
files, disable accounts, or run arbitrary commands. If the user requests a
response action, explain that this read-only version can prepare a response
recommendation and evidence package, but cannot execute the action.

For every response, cover:
1. What was observed.
2. Why it may matter.
3. Confidence and supporting evidence.
4. A safe next step.

When evidence supports a security issue, use the finding fields supplied in the
tool schema. Do not invent indicators or claim compromise without evidence.

Approved checks:
""" + "\n".join(f"- {name}: {spec[1]}" for name, spec in ALLOWED_CHECKS.items())
SYSTEM_PROMPT += """

When the user asks to investigate the host for suspicious activity, use the
coordinated investigation snapshot. It collects the approved checks together
so you can correlate evidence across logs, processes, services, connections,
firewall state, scheduled tasks, and audit status.
"""


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_defensive_investigation",
            "description": "Collect a bounded read-only snapshot across the local host for defensive correlation.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_defensive_check",
            "description": "Run one approved read-only defensive security check.",
            "parameters": {
                "type": "object",
                "properties": {
                    "check_type": {
                        "type": "string",
                        "enum": list(ALLOWED_CHECKS),
                        "description": "The approved defensive check to run.",
                    },
                    "target": {
                        "type": "string",
                        "description": "A local file path, only for file_metadata or file_hash.",
                    },
                },
                "required": ["check_type"],
            },
        },
    }
]


class DefensiveSecurityAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def _call_model(self):
        return self.client.chat.completions.create(
            model=MODEL,
            messages=self.messages,
            tools=TOOLS,
            tool_choice="auto",
        )

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self._call_model()
        reply = response.choices[0].message
        turn_log = {
            "agent": "defensive_security",
            "tool_type": None,
            "target": None,
            "command": None,
            "returncode": None,
            "stdout": None,
            "stderr": None,
            "timed_out": False,
            "findings": [],
        }

        while reply.tool_calls:
            self.messages.append(reply)
            for tool_call in reply.tool_calls:
                args = json.loads(tool_call.function.arguments or "{}")
                try:
                    if tool_call.function.name == "run_defensive_investigation":
                        payload = run_investigation_snapshot()
                    else:
                        payload = run_check(args.get("check_type"), args.get("target"))
                except ValueError as exc:
                    payload = {"error": str(exc)}
                if payload.get("investigation"):
                    turn_log["tool_type"] = payload["investigation"]
                    turn_log["stdout"] = json.dumps(payload)[:12000]
                    turn_log["returncode"] = 0
                else:
                    turn_log.update({
                        "tool_type": payload.get("check_type"),
                        "target": args.get("target"),
                        "command": payload.get("command"),
                        "returncode": payload.get("returncode"),
                        "stdout": payload.get("stdout"),
                        "stderr": payload.get("stderr"),
                        "timed_out": payload.get("timed_out", False),
                    })
                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(payload),
                })
            response = self._call_model()
            reply = response.choices[0].message

        self.messages.append(reply)
        return reply.content or "The defensive check finished, but no summary was returned.", turn_log
