"""Terminal companion entry point and shell integration installer."""

from __future__ import annotations

import os
from pathlib import Path

from llm_config import get_groq_client
from orchestrator import Orchestrator
from terminal_agent import TerminalAgent

MARKER = "# >>> cyberprobe terminal companion >>>"
END_MARKER = "# <<< cyberprobe terminal companion <<<"
COMPANION_SCRIPT = Path(__file__).resolve()
API_KEY_FILE = Path.home() / ".cyberprobe_groq_api_key"
MAX_EXPLAIN_OUTPUT = 12000

ZSH_HOOK = f'''{MARKER}
__cyberprobe_shell_cd() {{
  local request="$*"
  local target=""
  case "$request" in
    nvaigate[[:space:]]to[[:space:]]*) target="${{request#nvaigate to }}" ;;
    please[[:space:]]navigate[[:space:]]to[[:space:]]*) target="${{request#please navigate to }}" ;;
    please[[:space:]]nav[[:space:]]to[[:space:]]*) target="${{request#please nav to }}" ;;
    please[[:space:]]go[[:space:]]to[[:space:]]*) target="${{request#please go to }}" ;;
    navigate[[:space:]]to[[:space:]]*) target="${{request#navigate to }}" ;;
    nav[[:space:]]to[[:space:]]*) target="${{request#nav to }}" ;;
    go[[:space:]]to[[:space:]]*) target="${{request#go to }}" ;;
    cd[[:space:]]*) target="${{request#cd }}" ;;
    *) return 2 ;;
  esac
  target="${{target#the }}"
  target="${{target% folder}}"
  case "$target" in
    *';'*|*'|'*|*'&'*|*'$'*|*'`'*|*'<'*|*'>'*|*'('*|*')'*|*'\\n'*)
      print -u2 "CyberProbe: unsafe directory path rejected"
      return 2
      ;;
  esac
  case "$target" in
    Desktop|desktop) target="$HOME/Desktop" ;;
    Downloads|downloads) target="$HOME/Downloads" ;;
    Download|download|Downlaod|downlaod) target="$HOME/Downloads" ;;
    Documents|documents) target="$HOME/Documents" ;;
    Home|home|~) target="$HOME" ;;
    '~/'*) target="$HOME/${{target#~/}}" ;;
  esac
  builtin cd -- "$target" || return $?
  printf 'CyberProbe: current directory is %s\\n' "$PWD"
  return 0
}}
__cyberprobe_shell_cd_and_list() {{
  local request="$*"
  local target=""
  case "$request" in
    move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#move to }}" ;;
    go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#go to }}" ;;
    navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#navigate to }}" ;;
    *) return 1 ;;
  esac
  target="${{target%% and *}}"
  __cyberprobe_shell_cd "navigate to $target" || return $?
  printf 'CyberProbe: contents of %s\\n' "$PWD"
  command ls -la -- "$PWD"
}}
__cyberprobe_current_shell_action() {{
  local action=""
  local answer=""
  local out_file=""
  local err_file=""
  local status_file=""
  local command_status=0
  local final_status=0
  local proposed_command=""
  local thinking_pid=""
  (
    local frame=0
    local dots=""
    while true; do
      case $frame in
        0) dots="." ;;
        1) dots=".." ;;
        *) dots="..." ;;
      esac
      printf '\\rthinking %s' "$dots"
      frame=$(((frame + 1) % 3))
      sleep 0.35
    done
  ) &
  thinking_pid=$!
  action="$(CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --shell-action "$*" 2>/dev/null)"
  local planner_status=$?
  kill "$thinking_pid" 2>/dev/null
  wait "$thinking_pid" 2>/dev/null
  printf '\\r%s\\r' '                    '
  [[ $planner_status -ne 0 ]] && return 1
  printf '[Orchestrator -> Terminal Operations Agent]\\n'
  [[ -z "$action" ]] && return 1
  printf 'Proposed terminal action:\\n%s\\n\\n' "$action"
  read -r "?Run? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES)
      out_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-out.XXXXXX")" || return 1
      err_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-err.XXXXXX")" || {{ rm -f "$out_file"; return 1; }}
      status_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-status.XXXXXX")" || {{ rm -f "$out_file" "$err_file"; return 1; }}
      while IFS= read -r proposed_command || [[ -n "$proposed_command" ]]; do
        [[ -z "$proposed_command" ]] && continue
        eval "$proposed_command" > >(tee -a "$out_file") 2> >(tee -a "$err_file" >&2)
        command_status=$?
        printf '%s\\t%s\\n' "$command_status" "$proposed_command" >> "$status_file"
        if [[ $command_status -ne 0 ]]; then
          final_status=$command_status
          break
        fi
      done <<< "$action"
      python3 "{COMPANION_SCRIPT}" --explain-shell-action "$*" --status-file "$status_file" --stdout-file "$out_file" --stderr-file "$err_file"
      rm -f "$out_file" "$err_file" "$status_file"
      return $final_status
      ;;
    *)
      printf 'CyberProbe: cancelled.\\n'
      return 130
      ;;
  esac
}}
cyberprobe() {{
  if [[ "$1" == help ]]; then
    python3 "{COMPANION_SCRIPT}" --local-help
    return 0
  fi
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
  if [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" != 1 ]]; then
    __cyberprobe_current_shell_action "$@"
    local cyberprobe_action_status=$?
    [[ $cyberprobe_action_status -ne 1 ]] && return $cyberprobe_action_status
  fi
  CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$*"
}}
command_not_found_handler() {{
  local line="$*"
  [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && {{ print -u2 "zsh: command not found: $1"; return 127; }}
  __cyberprobe_current_shell_action "$line"
  local cyberprobe_action_status=$?
  [[ $cyberprobe_action_status -ne 1 ]] && return $cyberprobe_action_status
  __cyberprobe_shell_cd_and_list "$line" && return 0
  case "$line" in
    please[[:space:]]navigate[[:space:]]to[[:space:]]*|please[[:space:]]nav[[:space:]]to[[:space:]]*|please[[:space:]]go[[:space:]]to[[:space:]]*|navigate[[:space:]]to[[:space:]]*|nvaigate[[:space:]]to[[:space:]]*|nav[[:space:]]to[[:space:]]*|go[[:space:]]to[[:space:]]*|cd[[:space:]]*) __cyberprobe_shell_cd "$line"; return $? ;;
  esac
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
__cyberprobe_shell_cd() {{
  local request="$*"
  local target=""
  case "$request" in
    nvaigate[[:space:]]to[[:space:]]*) target="${{request#nvaigate to }}" ;;
    please[[:space:]]navigate[[:space:]]to[[:space:]]*) target="${{request#please navigate to }}" ;;
    please[[:space:]]nav[[:space:]]to[[:space:]]*) target="${{request#please nav to }}" ;;
    please[[:space:]]go[[:space:]]to[[:space:]]*) target="${{request#please go to }}" ;;
    navigate[[:space:]]to[[:space:]]*) target="${{request#navigate to }}" ;;
    nav[[:space:]]to[[:space:]]*) target="${{request#nav to }}" ;;
    go[[:space:]]to[[:space:]]*) target="${{request#go to }}" ;;
    cd[[:space:]]*) target="${{request#cd }}" ;;
    *) return 2 ;;
  esac
  target="${{target#the }}"
  target="${{target% folder}}"
  case "$target" in
    *';'*|*'|'*|*'&'*|*'$'*|*'`'*|*'<'*|*'>'*|*'('*|*')'*|*'\\n'*)
      printf 'CyberProbe: unsafe directory path rejected\\n' >&2
      return 2
      ;;
  esac
  case "$target" in
    Desktop|desktop) target="$HOME/Desktop" ;;
    Downloads|downloads) target="$HOME/Downloads" ;;
    Download|download|Downlaod|downlaod) target="$HOME/Downloads" ;;
    Documents|documents) target="$HOME/Documents" ;;
    Home|home|~) target="$HOME" ;;
    '~/'*) target="$HOME/${{target#~/}}" ;;
  esac
  builtin cd -- "$target" || return $?
  printf 'CyberProbe: current directory is %s\\n' "$PWD"
  return 0
}}
__cyberprobe_shell_cd_and_list() {{
  local request="$*"
  local target=""
  case "$request" in
    move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|move[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#move to }}" ;;
    go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|go[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#go to }}" ;;
    navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]list*|navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]show*|navigate[[:space:]]to[[:space:]]*[[:space:]]and[[:space:]]what*) target="${{request#navigate to }}" ;;
    *) return 1 ;;
  esac
  target="${{target%% and *}}"
  __cyberprobe_shell_cd "navigate to $target" || return $?
  printf 'CyberProbe: contents of %s\\n' "$PWD"
  command ls -la -- "$PWD"
}}
__cyberprobe_current_shell_action() {{
  local action=""
  local answer=""
  local out_file=""
  local err_file=""
  local status_file=""
  local command_status=0
  local final_status=0
  local proposed_command=""
  local thinking_pid=""
  (
    local frame=0
    local dots=""
    while true; do
      case $frame in
        0) dots="." ;;
        1) dots=".." ;;
        *) dots="..." ;;
      esac
      printf '\\rthinking %s' "$dots"
      frame=$(((frame + 1) % 3))
      sleep 0.35
    done
  ) &
  thinking_pid=$!
  action="$(CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --shell-action "$*" 2>/dev/null)"
  local planner_status=$?
  kill "$thinking_pid" 2>/dev/null
  wait "$thinking_pid" 2>/dev/null
  printf '\\r%s\\r' '                    '
  [[ $planner_status -ne 0 ]] && return 1
  printf '[Orchestrator -> Terminal Operations Agent]\\n'
  [[ -z "$action" ]] && return 1
  printf 'Proposed terminal action:\\n%s\\n\\n' "$action"
  read -r -p "Run? [y/N] " answer
  case "$answer" in
    y|Y|yes|YES)
      out_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-out.XXXXXX")" || return 1
      err_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-err.XXXXXX")" || {{ rm -f "$out_file"; return 1; }}
      status_file="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-status.XXXXXX")" || {{ rm -f "$out_file" "$err_file"; return 1; }}
      while IFS= read -r proposed_command || [[ -n "$proposed_command" ]]; do
        [[ -z "$proposed_command" ]] && continue
        eval "$proposed_command" > >(tee -a "$out_file") 2> >(tee -a "$err_file" >&2)
        command_status=$?
        printf '%s\\t%s\\n' "$command_status" "$proposed_command" >> "$status_file"
        if [[ $command_status -ne 0 ]]; then
          final_status=$command_status
          break
        fi
      done <<< "$action"
      python3 "{COMPANION_SCRIPT}" --explain-shell-action "$*" --status-file "$status_file" --stdout-file "$out_file" --stderr-file "$err_file"
      rm -f "$out_file" "$err_file" "$status_file"
      return $final_status
      ;;
    *)
      printf 'CyberProbe: cancelled.\\n'
      return 130
      ;;
  esac
}}
cyberprobe() {{
  if [[ "$1" == help ]]; then
    python3 "{COMPANION_SCRIPT}" --local-help
    return 0
  fi
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
  if [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" != 1 ]]; then
    __cyberprobe_current_shell_action "$@"
    local cyberprobe_action_status=$?
    [[ $cyberprobe_action_status -ne 1 ]] && return $cyberprobe_action_status
  fi
  CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --request "$*"
}}
command_not_found_handle() {{
  local line="$*"
  [[ "${{CYBERPROBE_COMPANION_DISABLED:-0}}" == 1 ]] && {{ printf 'bash: %s: command not found\\n' "$1" >&2; return 127; }}
  __cyberprobe_current_shell_action "$line"
  local cyberprobe_action_status=$?
  [[ $cyberprobe_action_status -ne 1 ]] && return $cyberprobe_action_status
  __cyberprobe_shell_cd_and_list "$line" && return 0
  case "$line" in
    please[[:space:]]navigate[[:space:]]to[[:space:]]*|please[[:space:]]nav[[:space:]]to[[:space:]]*|please[[:space:]]go[[:space:]]to[[:space:]]*|navigate[[:space:]]to[[:space:]]*|nvaigate[[:space:]]to[[:space:]]*|nav[[:space:]]to[[:space:]]*|go[[:space:]]to[[:space:]]*|cd[[:space:]]*) __cyberprobe_shell_cd "$line"; return $? ;;
  esac
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
        if not os.environ.get("GROQ_API_KEY") and API_KEY_FILE.exists():
            saved_key = API_KEY_FILE.read_text(encoding="utf-8").strip()
            if saved_key:
                os.environ["GROQ_API_KEY"] = saved_key
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


def print_shell_action(request: str) -> int:
    if not request.strip():
        return 3
    try:
        if not os.environ.get("GROQ_API_KEY") and API_KEY_FILE.exists():
            saved_key = API_KEY_FILE.read_text(encoding="utf-8").strip()
            if saved_key:
                os.environ["GROQ_API_KEY"] = saved_key
        agent = TerminalAgent(get_groq_client())
        action = agent.make_current_shell_action(
            f"Terminal context: current directory is {Path.cwd()}, "
            f"home directory is {Path.home()}.\n"
            f"User request: {request}"
        )
    except Exception:
        return 3
    if not action.get("ok"):
        return 3
    print(action["display"])
    return 0


def _read_limited(path: str | None, limit: int = MAX_EXPLAIN_OUTPUT) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _read_statuses(path: str | None) -> list[dict]:
    rows = []
    for line in _read_limited(path).splitlines():
        status, separator, command = line.partition("\t")
        if not separator:
            continue
        try:
            returncode = int(status)
        except ValueError:
            returncode = 1
        rows.append({"command": command, "returncode": returncode})
    return rows


def _markdown_escape(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def _command_label(command: str) -> str:
    first = command.strip().split(maxsplit=1)[0] if command.strip() else "command"
    return first


def _command_outcome(command: str, returncode: int, stdout: str, stderr: str) -> str:
    if returncode != 0:
        detail = stderr.strip().splitlines()[0] if stderr.strip() else "The command returned a non-zero status."
        return f"Failed: {detail}"
    stripped = command.strip()
    if stripped.startswith("cd "):
        return "Successfully changed the current terminal directory."
    if stripped.startswith("ls "):
        return "Directory listing returned successfully."
    if stripped == "pwd":
        return "Current directory printed successfully."
    if stripped.startswith("mkdir "):
        return "Directory creation completed successfully."
    if stripped.startswith("touch "):
        return "File timestamp/create operation completed successfully."
    if stripped.startswith("cp "):
        return "Copy operation completed successfully."
    if stripped.startswith("mv "):
        return "Move/rename operation completed successfully."
    if stripped.startswith("rm ") or stripped.startswith("rmdir "):
        return "Removal operation completed successfully."
    if stdout.strip():
        return "Command completed successfully and returned output."
    return "Command completed successfully."


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    word = singular if count == 1 else (plural or singular + "s")
    return f"{count} {word}"


def _parse_ls_listing(stdout: str) -> tuple[list[str], list[str]]:
    files = []
    folders = []
    for line in stdout.splitlines():
        if not line or line.startswith("total "):
            continue
        parts = line.split(maxsplit=8)
        if len(parts) < 9:
            continue
        permissions = parts[0]
        name = parts[8]
        if name in {".", ".."}:
            continue
        if permissions.startswith("d"):
            folders.append(name)
        elif permissions.startswith("-"):
            files.append(name)
    return files, folders


def _summarize_names(names: list[str], limit: int = 8) -> str:
    if not names:
        return ""
    shown = names[:limit]
    suffix = "" if len(names) <= limit else f", and {len(names) - limit} more"
    return ", ".join(shown) + suffix


def _interpret_command(command: str, returncode: int, stdout: str, stderr: str) -> str:
    stripped = command.strip()
    if returncode != 0:
        detail = stderr.strip().splitlines()[0] if stderr.strip() else "the command returned a non-zero status"
        return f"`{stripped}` did not complete successfully because {detail}."

    if stripped.startswith("ls "):
        files, folders = _parse_ls_listing(stdout)
        pieces = ["CyberProbe listed the requested folder contents."]
        if folders:
            pieces.append(f"It found {_plural(len(folders), 'folder')}: {_summarize_names(folders)}.")
        else:
            pieces.append("It did not show any folders in that listing.")
        if files:
            pieces.append(f"It found {_plural(len(files), 'file')}: {_summarize_names(files)}.")
        else:
            pieces.append("It did not show any regular files in that listing.")
        pieces.append("Nothing was changed on your computer because `ls` is read-only.")
        return " ".join(pieces)

    if stripped.startswith("cd "):
        target = stripped.split(" -- ", 1)[1] if " -- " in stripped else stripped[3:].strip()
        return f"CyberProbe changed your current terminal directory to `{target}`. This affects the terminal session you are using now."

    if stripped == "pwd":
        current = stdout.strip().splitlines()[-1] if stdout.strip() else "the current directory"
        return f"CyberProbe printed your current terminal directory: `{current}`."

    if stripped.startswith("mkdir "):
        return "CyberProbe created the requested directory path. This changed the filesystem."
    if stripped.startswith("touch "):
        return "CyberProbe created the requested file if it did not exist, or updated its timestamp if it already existed."
    if stripped.startswith("cp "):
        return "CyberProbe copied the requested item to the destination path."
    if stripped.startswith("mv "):
        return "CyberProbe moved or renamed the requested item."
    if stripped.startswith("rm ") or stripped.startswith("rmdir "):
        return "CyberProbe removed the requested item."

    if stdout.strip():
        line_count = len(stdout.splitlines())
        return f"CyberProbe ran the command successfully and it returned {_plural(line_count, 'line')} of output."
    return "CyberProbe ran the command successfully and it did not return any output."


def explain_shell_action(request: str, status_file: str | None, stdout_file: str | None, stderr_file: str | None) -> int:
    results = _read_statuses(status_file)
    stdout = _read_limited(stdout_file)
    stderr = _read_limited(stderr_file, 3000)
    if not results:
        print("\nCyberProbe explanation:\nNo terminal action results were captured.")
        return 1

    print("\n[CyberProbe → Terminal Action Summary]")
    print("**Plan:**\n")
    for index, result in enumerate(results, start=1):
        command = result["command"].strip()
        label = _command_label(command)
        if label == "cd":
            print(f"{index}. Change the current terminal directory.")
        elif label == "ls":
            print(f"{index}. List files and folders.")
        else:
            print(f"{index}. Run `{command}`.")

    print("\n**Results:**\n")
    print("| Step | Command executed | Return code | Outcome |")
    print("| --- | --- | --- | --- |")
    for result in results:
        command = result["command"].strip()
        returncode = result["returncode"]
        outcome = _command_outcome(command, returncode, stdout, stderr)
        print(
            f"| {_markdown_escape(_command_label(command))} "
            f"| `{_markdown_escape(command)}` "
            f"| {returncode} "
            f"| {_markdown_escape(outcome)} |"
        )

    print("\n**What happened:**\n")
    for result in results:
        command = result["command"].strip()
        explanation = _interpret_command(command, result["returncode"], stdout, stderr)
        print(f"- {explanation}")

    failures = [result for result in results if result["returncode"] != 0]
    completed = [result for result in results if result["returncode"] == 0]
    if failures:
        print(
            f"\n**What completed:** {len(completed)} of {len(results)} command(s) succeeded before CyberProbe stopped."
        )
        failed = failures[0]
        print(
            f"**What failed:** `{failed['command']}` returned code {failed['returncode']}."
        )
    else:
        print(
            f"\n**What completed:** All {len(results)} terminal command(s) succeeded. "
            "The action ran in your current shell environment."
        )
        print("**What failed:** None. There were no non-zero return codes.")

    return 0


def print_local_help() -> int:
    print("""CyberProbe terminal companion:
  cyberprobe help                         Show this help
  cyberprobe auth on/off/status           Allow or block terminal changes
  cyberprobe companion on/off/status      Enable or disable the companion
  cyberprobe analyze this file sample.pdf Send a request to CyberProbe
  cyberprobe go to Documents and list     Propose, ask, then run locally

Natural-language requests can also be typed without the cyberprobe prefix
when the companion is enabled, for example:
  analyze this file sample.pdf
  create a folder called games on Desktop

Terminal actions are shown first and run only after you answer yes:
  thinking .
  thinking ..
  thinking ...
  [Orchestrator -> Terminal Operations Agent]
  Proposed terminal action:
  cd -- /home/you/Documents
  ls -la -- /home/you/Documents

  Run? [y/N]

After the action runs, CyberProbe explains what happened in plain language,
then shows return codes and a short success/failure summary.
""")
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="CyberProbe terminal companion")
    parser.add_argument("--request", help="Send a natural-language request to CyberProbe")
    parser.add_argument("--shell-action", help="Print an allowlisted shell action for the current shell")
    parser.add_argument("--explain-shell-action", help="Explain a shell action that already ran")
    parser.add_argument("--status-file", help="Path to captured command status records")
    parser.add_argument("--stdout-file", help="Path to captured stdout")
    parser.add_argument("--stderr-file", help="Path to captured stderr")
    parser.add_argument("--local-help", action="store_true", help="Show companion help without using the API")
    args = parser.parse_args()
    if args.local_help:
        return print_local_help()
    if args.shell_action is not None:
        return print_shell_action(args.shell_action)
    if args.explain_shell_action is not None:
        return explain_shell_action(args.explain_shell_action, args.status_file, args.stdout_file, args.stderr_file)
    if args.request is None:
        parser.error("--request is required")
    return run_request(args.request)


if __name__ == "__main__":
    raise SystemExit(main())
