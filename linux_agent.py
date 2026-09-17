"""
linux_agent.py

Specialized agent for Linux system inspection via allowlisted tools.
The agent never constructs raw commands -- it only picks tool_type names
from linux_tools.ALLOWED_TOOLS.
"""

import json

from llm_config import MODEL
from linux_tools import ALLOWED_TOOLS, run_tool

SYSTEM_PROMPT = f"""You are the Linux System Agent inside CyberProbe -- a
friendly Linux host inspection specialist for complete beginners. The user may
not know what a kernel, process, service, mount point, or socket is unless you
explain it.

You inspect Linux systems the user has access to.

You can only use the `run_linux_tool` tool, and only with one of these
tool_type values:

{chr(10).join(f"- {name}: {spec['description']}" for name, spec in ALLOWED_TOOLS.items())}

Your job, every turn:
1. Ask a short clarifying question if you don't know what the user wants to
   inspect yet.
2. Pick the most appropriate tool_type and call run_linux_tool. If the user
   asks for a broad system summary, start with `system_info`, `cpu_info`,
   `memory_usage`, or `disk_usage` depending on the angle they seem to care
   about most.
3. After a tool result comes back, explain it in plain, jargon-free language:
   - What was found in plain terms
   - Why it matters / what it could mean
   - What a reasonable next step might be
   Define technical terms the first time you use them.
4. Never dump raw output without explaining it.
5. If the user asks for something outside this allowlist, say so plainly and
   suggest the closest supported inspection instead.

Keep explanations concise but complete -- a beginner should finish reading and
understand both WHAT happened and WHY it matters.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_linux_tool",
            "description": (
                "Run an approved Linux inspection tool. Only use tool_type "
                "values from the allowlist."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_type": {
                        "type": "string",
                        "enum": list(ALLOWED_TOOLS.keys()),
                        "description": "Which allowed Linux tool to run.",
                    },
                    "target": {
                        "type": "string",
                        "description": (
                            "Optional user-provided target such as a service "
                            "name, user name, file path, or host name."
                        ),
                    },
                },
                "required": ["tool_type"],
            },
        },
    }
]


class LinuxAgent:
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

        if tool_call.function.name != "run_linux_tool":
            return json.dumps({"error": f"Unknown tool call: {tool_call.function.name}"})

        tool_type = args.get("tool_type")
        target = args.get("target")

        if tool_type not in ALLOWED_TOOLS:
            return json.dumps({"error": f"'{tool_type}' is not an allowed Linux tool."})

        print(f"\n[Linux Agent | Running: {ALLOWED_TOOLS[tool_type]['binary']} ...]")
        result = run_tool(tool_type, target)

        if result.timed_out:
            return json.dumps({
                "error": f"Linux tool timed out after {result.command}",
                "stderr": result.stderr,
            })

        return json.dumps({
            "tool_type": tool_type,
            "target": target,
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            "timed_out": result.timed_out,
        })

    def send(self, user_message: str) -> tuple[str, dict]:
        turn_log = {
            "agent": "linux",
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

                if tool_payload.get("tool_type"):
                    turn_log["tool_type"] = tool_payload.get("tool_type")
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

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result_json,
                })
            response = self._call_model()
            reply = response.choices[0].message

        self.messages.append(reply)
        return reply.content, turn_log
