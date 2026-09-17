"""Terminal companion entry point and shell integration installer."""

from __future__ import annotations

import os
from pathlib import Path

from orchestrator import Orchestrator

MARKER = "# >>> cyberprobe terminal companion >>>"
END_MARKER = "# <<< cyberprobe terminal companion <<<"
COMPANION_SCRIPT = Path(__file__).resolve()

ZSH_HOOK = f'''{MARKER}
cyberprobe() {{
  if [[ "$1" == companion && "$2" == on ]]; then
    unset CYBERPROBE_COMPANION_DISABLED
    printf 'CyberProbe terminal companion: ON\\n'
    return 0
  fi
  if [[ "$1" == companion && "$2" == off ]]; then
    export CYBERPROBE_COMPANION_DISABLED=1
    printf 'CyberProbe terminal companion: OFF\\n'
    return 0
  fi
  if [[ "$1" == companion && "$2" == status ]]; then
    [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && printf 'CyberProbe terminal companion: OFF\\n' || printf 'CyberProbe terminal companion: ON\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == on ]]; then
    export CYBERPROBE_AUTH=1
    printf 'CyberProbe terminal authorization: ON\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == off ]]; then
    unset CYBERPROBE_AUTH
    printf 'CyberProbe terminal authorization: OFF\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == status ]]; then
    [[ "${{CYBERPROBE_AUTH:-0}}" == 1 ]] && printf 'CyberProbe terminal authorization: ON\\n' || printf 'CyberProbe terminal authorization: OFF\\n'
    return 0
  fi
  CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$*"
}}
command_not_found_handler() {{
  local line="$*"
  [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && {{ print -u2 "zsh: command not found: $1"; return 127; }}
  case "$line" in
  analyze[[:space:]]*|check[[:space:]]*|explain[[:space:]]*|extract[[:space:]]*|find[[:space:]]*|hello[[:space:]]*|hi[[:space:]]*|how[[:space:]]*|inspect[[:space:]]*|investigate[[:space:]]*|is[[:space:]]*|list[[:space:]]*|look[[:space:]]*|run[[:space:]]*|scan[[:space:]]*|show[[:space:]]*|tell[[:space:]]*|what[[:space:]]*|why[[:space:]]*|can[[:space:]]*|create[[:space:]]*)
    CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$line"
    return 0
    ;;
  esac
  print -u2 "zsh: command not found: $1"
  return 127
}}
{END_MARKER}
'''

BASH_HOOK = f'''{MARKER}
cyberprobe() {{
  if [[ "$1" == companion && "$2" == on ]]; then
    unset CYBERPROBE_COMPANION_DISABLED
    printf 'CyberProbe terminal companion: ON\\n'
    return 0
  fi
  if [[ "$1" == companion && "$2" == off ]]; then
    export CYBERPROBE_COMPANION_DISABLED=1
    printf 'CyberProbe terminal companion: OFF\\n'
    return 0
  fi
  if [[ "$1" == companion && "$2" == status ]]; then
    [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && printf 'CyberProbe terminal companion: OFF\\n' || printf 'CyberProbe terminal companion: ON\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == on ]]; then
    export CYBERPROBE_AUTH=1
    printf 'CyberProbe terminal authorization: ON\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == off ]]; then
    unset CYBERPROBE_AUTH
    printf 'CyberProbe terminal authorization: OFF\\n'
    return 0
  fi
  if [[ "$1" == auth && "$2" == status ]]; then
    [[ "${{CYBERPROBE_AUTH:-0}}" == 1 ]] && printf 'CyberProbe terminal authorization: ON\\n' || printf 'CyberProbe terminal authorization: OFF\\n'
    return 0
  fi
  CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$*"
}}
command_not_found_handle() {{
  local line="$*"
  [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && {{ printf 'bash: %s: command not found\\n' "$1" >&2; return 127; }}
  if [[ "$line" =~ ^cyberprobe[[:space:]] ]]; then
    CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "${{line#cyberprobe }}"
    return 0
  fi
  if [[ "$line" =~ ^(analyze|check|explain|extract|find|hello|hi|how|inspect|investigate|is|list|look|run|scan|show|tell|what|why|can|create)[[:space:]] ]]; then
    CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$line"
    return 0
  fi
  printf 'bash: %s: command not found\\n' "$1" >&2
  return 127
}}
{END_MARKER}
'''


def _install_or_update(path: Path, block: str) -> str:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    path.parent.mkdir(parents=True, exist_ok=True)
    if MARKER in existing and END_MARKER in existing:
        start = existing.index(MARKER)
        end = existing.index(END_MARKER, start) + len(END_MARKER)
        updated = existing[:start] + block.rstrip("\n") + existing[end:]
        if updated != existing:
            path.write_text(updated, encoding="utf-8")
            return "updated"
        return "unchanged"
    with path.open("a", encoding="utf-8") as handle:
        if existing and not existing.endswith("\n"):
            handle.write("\n")
        handle.write("\n" + block)
    return "installed"


def deploy_companion() -> str:
    """Install shell hooks after explicit user confirmation."""
    shell = os.environ.get("SHELL", "")
    if shell.endswith("zsh"):
        targets = [(Path.home() / ".zshrc", ZSH_HOOK)]
    elif shell.endswith("bash"):
        targets = [(Path.home() / ".bashrc", BASH_HOOK)]
    else:
        targets = [(Path.home() / ".zshrc", ZSH_HOOK), (Path.home() / ".bashrc", BASH_HOOK)]

    print("CyberProbe will add a visible shell hook to: " + ", ".join(str(path) for path, _ in targets))
    print("It intercepts only CyberProbe requests and common natural-language requests.")
    answer = input("Deploy the terminal companion? (yes/no): ").strip().lower()
    if answer not in {"y", "yes"}:
        return "Terminal companion deployment cancelled."

    results = [_install_or_update(path, block) for path, block in targets]
    if all(result == "unchanged" for result in results):
        return "Terminal companion is already deployed. Open a new terminal to use it."
    return "Terminal companion deployed or updated. Open a new terminal, then try: analyze this file sample.pdf"


def run_request(request: str) -> int:
    if not request.strip():
        print('Usage: cyberprobe --request "your question"')
        return 2
    try:
        agent = Orchestrator()
        context = (
            f"Terminal context: current directory is {Path.cwd()}, "
            f"home directory is {Path.home()}.\n"
        )
        print(agent.send(context + "User request: " + request))
    except Exception as error:
        print(f"CyberProbe companion error: {error}")
        return 1
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CyberProbe terminal companion")
    parser.add_argument("--request", help="Send a natural-language request to CyberProbe")
    args = parser.parse_args()
    if args.request is None:
        parser.error("--request is required")
    return run_request(args.request)


if __name__ == "__main__":
    raise SystemExit(main())
