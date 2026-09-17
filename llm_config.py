"""
llm_config.py

Shared Groq client and model configuration for all agents.
"""

import os

from groq import Groq

MODEL = "openai/gpt-oss-120b"


def get_groq_client() -> Groq:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY environment variable is not set. "
            "Get a free key at https://console.groq.com and run:\n"
            "  export GROQ_API_KEY=your_key_here"
        )
    return Groq(api_key=api_key)
