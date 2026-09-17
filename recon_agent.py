"""
recon_agent.py

 Specialized agent for network reconnaissance via allowlisted tools.
The agent never constructs raw commands -- it only picks scan_type names
from security_tools.ALLOWED_SCANS.
"""

import json
from finding_model import finding_schema

from llm_config import MODEL
from security_tools import (
    ALLOWED_SCANS,
    RECON_CAPABILITIES,
    TargetValidationError,
    confirm_and_maybe_sudo,
    run_scan,
    run_recon_capability,
    validate_target,
)

SYSTEM_PROMPT = f"""You are the Recon Agent inside CyberProbe -- a friendly network
reconnaissance specialist for complete beginners. The user has zero security
background; assume they do not know what a port, a service, or a scan type is
unless you explain it.

You help them investigate authorized targets using approved reconnaissance tools.

You can use the `run_recon_tool` tool with one of these capability values:

{chr(10).join(f"- {name}: {spec[1]}" for name, spec in RECON_CAPABILITIES.items())}

Your job, every turn:
1. Ask for a target IP/hostname if you don't have one yet.
2. Pick the most appropriate capability and call run_recon_tool. If you're not
   sure which scan fits, ask a simple clarifying question first (e.g. "want a
   quick check, or a deeper look at what's running?").
3. After a tool result comes back, explain it in plain, jargon-free language:
   - What was found in plain terms
   - Why it matters / what it could mean
   - What a reasonable next step might be
   Define any technical term the first time you use it.
4. Never assume the user knows terminology. Never dump raw tool output without
   explaining it.
5. Only ever scan targets the user gives you.

When a security issue is supported by the evidence, describe it using these
finding fields: title, severity, confidence, evidence, affected_asset, impact,
remediation, and recommended_validation. Do not invent findings.

Keep explanations concise but complete -- a beginner should finish reading and
understand both WHAT happened and WHY it matters.

Every response must end with:
## NEXT MOVES
3–5 numbered, short options the user can pick for the next step.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_recon_tool",
            "description": (
                "Run one approved reconnaissance capability against a user-supplied "
                "target. Never construct a raw command."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "enum": list(RECON_CAPABILITIES.keys()),
                        "description": "Which approved recon capability to run.",
                    },
                    "target": {
                        "type": "string",
                        "description": "IP address or hostname to scan.",
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port list such as 22,80,443; only used for selected_ports_nmap.",
                    },
                },
                "required": ["capability", "target"],
            },
        },
    }
]


class ReconAgent:
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

    def _execute_tool_call(self, tool_call):
        args = json.loads(tool_call.function.arguments)

        if tool_call.function.name != "run_recon_tool":
            return json.dumps({"error": f"Unknown tool call: {tool_call.function.name}"})

        capability = args.get("capability")
        target = args.get("target")
        ports = args.get("ports")

        try:
            validate_target(target)
        except TargetValidationError as e:
            return json.dumps({"error": str(e)})

        if capability not in RECON_CAPABILITIES:
            return json.dumps({"error": f"'{capability}' is not an allowed recon capability."})

        print(f"\n[Recon Agent | Running: {capability} against {target} ...]")
        result = run_recon_capability(capability, target, ports)

        if result.timed_out:
            return json.dumps({
                "error": f"Scan timed out after {result.command}",
                "stderr": result.stderr,
            })

        return json.dumps({
            "scan_type": capability,
            "target": target,
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            "timed_out": result.timed_out,
        })

    def send(self, user_message: str) -> tuple[str, dict]:
        """
        Process a recon request. Returns (reply_text, turn_metadata).
        """
        turn_log = {
            "agent": "recon",
            "scan_type": None,
            "target": None,
            "command": None,
            "returncode": None,
            "stdout": None,
            "stderr": None,
            "timed_out": False,
            "declined_sudo": False,
            "tool_type": None,
            "file_path": None,
            "file_hash": None,
        }
        self.messages.append({"role": "user", "content": user_message})

        response = self._call_model()
        reply = response.choices[0].message

        while reply.tool_calls:
            self.messages.append(reply)
            for tool_call in reply.tool_calls:
                result_json = self._execute_tool_call(tool_call)
                try:
                    tool_payload = json.loads(result_json)
                except json.JSONDecodeError:
                    tool_payload = {}

                if tool_payload.get("scan_type"):
                    turn_log["scan_type"] = tool_payload.get("scan_type")
                if tool_payload.get("target"):
                    turn_log["target"] = tool_payload.get("target")
                if tool_payload.get("command"):
                    turn_log["command"] = tool_payload.get("command")
                if "returncode" in tool_payload:
                    turn_log["returncode"] = tool_payload.get("returncode")
                if "stdout" in tool_payload:
                    turn_log["stdout"] = tool_payload.get("stdout")
                if "stderr" in tool_payload:
                    turn_log["stderr"] = tool_payload.get("stderr")
                if "timed_out" in tool_payload:
                    turn_log["timed_out"] = tool_payload.get("timed_out", False)
                if tool_payload.get("error") == "User declined to grant admin privileges. Scan was not run.":
                    turn_log["declined_sudo"] = True

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_json,
                })
            response = self._call_model()
            reply = response.choices[0].message

        self.messages.append(reply)
        return reply.content, turn_log
