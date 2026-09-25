"""Metasploit specialist with automatic module discovery and confirmation."""

import json
from llm_config import MODEL
from metasploit_tools import discover_modules, run_approved_module

SYSTEM_PROMPT = """You are CyberProbe's Metasploit Agent. Use Metasploit only for an explicitly supplied, authorized target. First search the installed Metasploit module database when a module is not known. Select only a module returned by that search; never invent modules or commands. The execution tool displays the exact target and module and asks for yes/no confirmation immediately before execution. Report facts, console evidence, session status, and uncertainty. Never claim code execution or access unless the output proves it."""

TOOLS = [
    {"type": "function", "function": {"name": "search_metasploit_modules", "description": "Search modules installed in the local Metasploit database without executing anything.", "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {"name": "run_metasploit_module", "description": "Run one module discovered in the local Metasploit database after confirmation.", "parameters": {"type": "object", "properties": {"target": {"type": "string"}, "module": {"type": "string"}, "rport": {"type": "integer"}, "payload": {"type": "string"}}, "required": ["target", "module"]}}},
]


class MetasploitAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
        reply = response.choices[0].message
        log = {"agent": "metasploit", "tool_type": "metasploit_module", "target": None, "command": None, "returncode": None, "stdout": None, "stderr": None, "timed_out": False}
        while reply.tool_calls:
            self.messages.append(reply)
            for call in reply.tool_calls:
                args = json.loads(call.function.arguments or "{}")
                try:
                    if call.function.name == "search_metasploit_modules":
                        result = discover_modules(args.get("query"))
                    else:
                        result = run_approved_module(target=args.get("target"), module=args.get("module"), rport=args.get("rport"), payload=args.get("payload"))
                except (ValueError, RuntimeError) as exc:
                    result = {"error": str(exc), "returncode": 2}
                log.update({k: result.get(k) for k in ("target", "command", "returncode", "stdout", "stderr", "timed_out")})
                self.messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})
            response = self.client.chat.completions.create(model=MODEL, messages=self.messages, tools=TOOLS, tool_choice="auto")
            reply = response.choices[0].message
        self.messages.append(reply)
        return reply.content or "Metasploit returned no summary.", log
