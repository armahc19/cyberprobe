"""
logger.py

Minimal JSONL turn logger for CyberProbe.
Keeps all file I/O isolated here so the agent and security tools stay focused
on conversation and scanning logic.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

LOG_DIR = "logs"
MAX_FIELD_CHARS = 4000
MAX_TEXT_CHARS = 2000


def new_session_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"session_{timestamp}_{uuid.uuid4().hex}"


def _safe_text(value, limit=MAX_TEXT_CHARS):
    if value is None:
        return None
    text = str(value)
    return text[:limit]


def _safe_field(value, limit=MAX_FIELD_CHARS):
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple)):
        try:
            text = json.dumps(value, ensure_ascii=True)
        except Exception:
            text = str(value)
    else:
        text = str(value)
    return text[:limit]


def log_turn(
    *,
    session_id,
    user_message,
    agent,
    scan_type,
    target,
    tool_type,
    file_path,
    file_hash,
    command,
    returncode,
    stdout,
    stderr,
    timed_out,
    declined_sudo,
    agent_explanation,
    findings=None,
):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "user_message": _safe_text(user_message),
        "agent": _safe_field(agent),
        "scan_type": _safe_field(scan_type),
        "target": _safe_field(target),
        "tool_type": _safe_field(tool_type),
        "file_path": _safe_field(file_path),
        "file_hash": _safe_field(file_hash),
        "command": _safe_field(command),
        "returncode": returncode,
        "stdout": _safe_text(stdout),
        "stderr": _safe_text(stderr),
        "timed_out": bool(timed_out),
        "declined_sudo": bool(declined_sudo),
        "agent_explanation": _safe_text(agent_explanation),
        "findings": _safe_field(findings or [], limit=12000),
    }

    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.join(LOG_DIR, f"{session_id}.jsonl")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True) + "\n")
    except Exception:
        pass
