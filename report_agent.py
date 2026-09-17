"""Specialist agent for producing consistent CyberProbe assessment reports."""
from llm_config import MODEL
from finding_model import SEVERITIES

SYSTEM_PROMPT = """You are CyberProbe's Report Agent. Turn supplied agent results and findings into a clear defensive security report for a beginner or technical reviewer.

Use this order: Executive summary; Scope and assets; Prioritized findings; Evidence and confidence; Remediation plan; Recommended validation.

Every finding must preserve its title, severity, confidence, evidence, affected asset, impact, remediation, and recommended validation. Do not invent CVEs, evidence, affected assets, or confirmed risks. Separate observed facts from assumptions. If information is missing, say so. The user may request Markdown or JSON; default to concise Markdown.""" + f"\nAllowed severities: {', '.join(SEVERITIES)}."

class ReportAgent:
    def __init__(self, client):
        self.client = client
        self.messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    def send(self, user_message: str) -> tuple[str, dict]:
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(model=MODEL, messages=self.messages)
        reply = response.choices[0].message
        self.messages.append(reply)
        return reply.content, {"agent": "report", "tool_type": None, "target": None, "command": None, "returncode": None, "stdout": None, "stderr": None, "timed_out": False}
