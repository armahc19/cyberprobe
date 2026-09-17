"""
forensics_agent.py

Specialized agent for file forensics via allowlisted tools.
The agent never constructs raw commands -- it only picks tool_type names
from forensics_tools.ALLOWED_TOOLS.
"""

import json

from forensics_tools import ALLOWED_TOOLS, FileValidationError, run_tool
from llm_config import MODEL

SYSTEM_PROMPT = f"""You are the Forensics Agent inside CyberProbe -- a friendly file
analysis specialist for complete beginners. The user has zero security background;
assume they do not know forensics terminology unless you explain it.

You help them analyze files, memory images, and disk or filesystem images
they provide by path. Analysis is performed on a staged copy so the original
evidence is preserved.

You can only use the `run_forensics_tool` tool, and only with one of these
tool_type values:

{chr(10).join(f"- {name}: {spec['description']}" for name, spec in ALLOWED_TOOLS.items())}

Your job, every turn:
1. Ask for a file path if you don't have one yet.
2. Pick the most appropriate tool_type and call run_forensics_tool. The tool
   copies the input into a local forensics_evidence folder, computes a hash for
   the staged copy, and runs analysis on that copy so the original is preserved.
   Memory analysis, disk layout inspection, filesystem analysis, data carving,
   and deleted-file recovery are available for compatible image files. Carved
   and recovered output is written only to a separate evidence subfolder.
   If you're not sure which tool fits, ask a simple clarifying question first
   (e.g. "want me to identify it, extract metadata, or look for hidden text?").
3. After a tool result comes back, explain it in plain, jargon-free language:
   - What was found in plain terms
   - Why it matters / what it could mean
   - What a reasonable next step might be
   Define any technical term the first time you use it.
4. Never assume the user knows terminology. Never dump raw tool output without
   explaining it.
5. Only ever analyze files the user gives you.

Keep explanations concise but complete -- a beginner should finish reading and
understand both WHAT happened and WHY it matters.
"""

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_forensics_tool",
            "description": (
                "Run an approved forensics tool against a file path provided "
                "by the user. The file will be copied into a local evidence "
                "folder and analyzed from there. Only use tool_type values "
                "from the allowlist."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "tool_type": {
                        "type": "string",
                        "enum": list(ALLOWED_TOOLS.keys()),
                        "description": "Which allowed forensics tool to run.",
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Any file path the user provides.",
                    },
                },
                "required": ["tool_type", "file_path"],
            },
        },
    }
]


class ForensicsAgent:
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

        if tool_call.function.name != "run_forensics_tool":
            return json.dumps({"error": f"Unknown tool call: {tool_call.function.name}"})

        tool_type = args.get("tool_type")
        file_path = args.get("file_path")

        if tool_type not in ALLOWED_TOOLS:
            return json.dumps({"error": f"'{tool_type}' is not an allowed forensics tool."})

        try:
            print(f"\n[Forensics Agent | Running: {ALLOWED_TOOLS[tool_type]['binary']} {file_path} ...]")
            result = run_tool(tool_type, file_path)
        except FileValidationError as e:
            return json.dumps({"error": str(e)})

        if result.timed_out:
            return json.dumps({
                "error": f"Forensics tool timed out after {result.command}",
                "stderr": result.stderr,
            })

        return json.dumps({
            "tool_type": tool_type,
            "original_path": file_path,
            "staged_path": result.staged_path,
            "file_hash": result.file_hash,
            "command": result.command,
            "returncode": result.returncode,
            "stdout": result.stdout[:8000],
            "stderr": result.stderr[:2000],
            "timed_out": result.timed_out,
        })

    def send(self, user_message: str) -> tuple[str, dict]:
        """
        Process a forensics request. Returns (reply_text, turn_metadata).
        """
        turn_log = {
            "agent": "forensics",
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
                if tool_payload.get("original_path"):
                    turn_log["file_path"] = tool_payload.get("original_path")
                if tool_payload.get("file_hash"):
                    turn_log["file_hash"] = tool_payload.get("file_hash")
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
