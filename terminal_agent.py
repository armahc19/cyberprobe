"""Natural-language interface for safe local terminal operations."""

import json

from llm_config import MODEL
from terminal_tools import OPERATIONS, run_terminal_operation

SYSTEM_PROMPT = f"""You are CyberProbe's Terminal Operations Agent. Help beginners
use their local Linux terminal. You may execute only an approved operation from
this list:

{chr(10).join(f'- {name}: {description}' for name, description in OPERATIONS.items())}

Translate requests into the correct operation and parameters. Explain results
plainly. State-changing operations run only when the user's terminal
authorization is ON (`auth on`). With authorization OFF, explain the requested
action but do not execute it.
When authorization is ON and the user asks you to create, copy, move, delete,
edit, install, change permissions, kill a process, or change a service, you
MUST call the matching operation instead of merely printing shell commands.
For multi-step requests, execute each applicable operation. A `cd` cannot
change the parent shell from this subprocess, so resolve later relative paths
against the supplied current directory and execute the requested file action.
Only explain how to do it manually when authorization is OFF or the operation
is not in the allowlist.
Never invent shell commands, bypass confirmation, use pipelines, or perform
actions outside the allowlist. For `cd`, explain that directory changes belong
to the user's shell and suggest the normal `cd` command. Do not expose secrets
from file contents in your explanation unless the user explicitly asks.
"""

TOOLS = [{"type": "function", "function": {"name": "run_terminal_operation", "description": "Run one approved local terminal operation.", "parameters": {"type": "object", "properties": {
    "operation": {"type": "string", "enum": list(OPERATIONS)},
    "path": {"type": "string"}, "destination": {"type": "string"}, "pattern": {"type": "string"},
    "content": {"type": "string"}, "package": {"type": "string"}, "mode": {"type": "string"},
    "owner": {"type": "string"}, "group": {"type": "string"}, "pid": {"type": "string"},
    "signal": {"type": "string"}, "service": {"type": "string"}, "action": {"type": "string"},
}, "required": ["operation"]}}}]


class TerminalAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
        reply = response.choices[0].message
        turn_log = {"agent": "terminal", "tool_type": None, "command": None, "returncode": None, "stdout": None, "stderr": None, "timed_out": False}
        while reply.tool_calls:
            self.messages.append(reply)
            for tool_call in reply.tool_calls:
                args = json.loads(tool_call.function.arguments)
                if tool_call.function.name != "run_terminal_operation":
                    result = {"error": "Unknown terminal tool."}
                else:
                    try:
                        result = run_terminal_operation(**args)
                    except (ValueError, OSError) as error:
                        result = {"error": str(error), "operation": args.get("operation")}
                    turn_log.update({"tool_type": result.get("operation"), "command": result.get("command"), "returncode": result.get("returncode"), "stdout": result.get("stdout"), "stderr": result.get("stderr"), "timed_out": result.get("timed_out", False)})
                self.messages.append({"role": "tool", "tool_call_id": tool_call.id, "content": json.dumps(result)})
            response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
            reply = response.choices[0].message
        self.messages.append(reply)
        return reply.content or "", turn_log
