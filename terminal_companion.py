"""Terminal companion entry point and shell integration installer."""

from __future__ import annotations

import json
import os
import shlex
import sys
from pathlib import Path

from llm_config import MODEL, get_groq_client
from orchestrator import Orchestrator
from terminal_agent import TerminalAgent

MARKER = "# >>> cyberprobe terminal companion >>>"
END_MARKER = "# <<< cyberprobe terminal companion <<<"
COMPANION_SCRIPT = Path(__file__).resolve()
API_KEY_FILE = Path.home() / ".cyberprobe_groq_api_key"
MAX_EXPLAIN_OUTPUT = 12000
MAX_OBSERVE_CAPTURE = 1_500_000
OBSERVE_CHUNK_SIZE = 5500
OBSERVE_MAX_CHUNKS = 24

OBSERVE_MAP_PROMPT = """You summarize one chunk of terminal command output for a beginner on Kali/Linux.
Return concise bullet notes only: what this section shows, important numbers or labels, and anything that looks wrong.
Do not repeat generic definitions. Do not invent values that are not in the chunk."""

OBSERVE_REDUCE_PROMPT = """You are CyberProbe's terminal-output explainer for beginners with no Linux background.
Merge the section notes into ONE explanation in plain language. Include:
- What the user ran and what that kind of command is for
- What the output means (success, failure, warnings, packet loss, HTTP codes, tool tags, etc.)
- One practical takeaway or next step
- If the command touched a website or remote target, remind them to use only authorized targets
Do not invent data. Stay under 450 words unless multiple serious errors need listing."""


def _observe_shell_block() -> str:
    script = shlex.quote(str(COMPANION_SCRIPT))
    return f"""
__cyberprobe_observe_skip_capture() {{
  case "$1" in
    cyberprobe\\ observe*|cyberprobe\\ explain|cyberprobe\\ help|cyberprobe\\ auth*|cyberprobe\\ companion*) return 0 ;;
  esac
  return 1
}}
__cyberprobe_is_interactive_cmd() {{
  local cmd="$1"
  local bin="${{cmd%% *}}"
  case "$bin" in
    vim|vi|nano|emacs|micro|htop|top|less|more|man|ssh|sftp|ftp|mysql|psql|sqlite3|msfconsole|burpsuite|su|login|passwd|telnet|ngrok|gdb|lldb)
      return 0 ;;
  esac
  case "$cmd" in
    python|python3|node|ruby|irb|ipython|pwsh|bash|zsh|sh|fish)
      case "$cmd" in
        *"-c "*|*"-c"*) return 1 ;;
        *) return 0 ;;
      esac
      ;;
  esac
  return 1
}}
__cyberprobe_observe_setup_files() {{
  __CP_OBS_DIR="${{TMPDIR:-/tmp}}/cyberprobe-observe.$$"
  mkdir -p "$__CP_OBS_DIR" || return 1
  __CP_CAP_OUT="$__CP_OBS_DIR/stdout.log"
  __CP_CAP_ERR="$__CP_OBS_DIR/stderr.log"
  __CP_OBS_STATE="$__CP_OBS_DIR/last.json"
  export __CP_OBS_DIR __CP_CAP_OUT __CP_CAP_ERR __CP_OBS_STATE
  : > "$__CP_CAP_OUT"
  : > "$__CP_CAP_ERR"
  __CP_CAP_OUT_START=0
  __CP_CAP_ERR_START=0
}}
__cyberprobe_observe_enable_tee() {{
  [[ -n "${{__CP_OBSERVE_TEE_ACTIVE:-}}" ]] && return 0
  __cyberprobe_observe_setup_files || return 1
  exec > >(tee -a "$__CP_CAP_OUT")
  exec 2> >(tee -a "$__CP_CAP_ERR" >&2)
  __CP_OBSERVE_TEE_ACTIVE=1
  export __CP_OBSERVE_TEE_ACTIVE
}}
__cyberprobe_observe_commit() {{
  local cmd="$1"
  local rc="$2"
  local interactive="$3"
  if [[ "$interactive" == 1 ]]; then
    CYBERPROBE_COMPANION=1 python3 {script} --write-observe-capture \\
      --observe-state-file "$__CP_OBS_STATE" \\
      --observe-command "$cmd" \\
      --observe-returncode "$rc" \\
      --observe-interactive
    return $?
  fi
  local out_slice err_slice
  out_slice="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-obs-out.XXXXXX")" || return 1
  err_slice="$(mktemp "${{TMPDIR:-/tmp}}/cyberprobe-obs-err.XXXXXX")" || {{ rm -f "$out_slice"; return 1; }}
  if [[ -f "$__CP_CAP_OUT" ]]; then
    tail -c +$(( __CP_CAP_OUT_START + 1 )) "$__CP_CAP_OUT" > "$out_slice" 2>/dev/null || : > "$out_slice"
  else
    : > "$out_slice"
  fi
  if [[ -f "$__CP_CAP_ERR" ]]; then
    tail -c +$(( __CP_CAP_ERR_START + 1 )) "$__CP_CAP_ERR" > "$err_slice" 2>/dev/null || : > "$err_slice"
  else
    : > "$err_slice"
  fi
  CYBERPROBE_COMPANION=1 python3 {script} --write-observe-capture \\
    --observe-state-file "$__CP_OBS_STATE" \\
    --observe-command "$cmd" \\
    --observe-returncode "$rc" \\
    --observe-stdout-file "$out_slice" \\
    --observe-stderr-file "$err_slice"
  local write_status=$?
  rm -f "$out_slice" "$err_slice"
  return $write_status
}}
__cyberprobe_observe_preexec() {{
  [[ "${{CYBERPROBE_OBSERVE:-0}}" != 1 ]] && return
  __CP_OBS_PENDING_CMD="$1"
  __CP_OBS_PENDING_INTERACTIVE=0
  if __cyberprobe_observe_skip_capture "$1"; then
    __CP_OBS_SKIP_CAPTURE=1
    return
  fi
  __CP_OBS_SKIP_CAPTURE=0
  if __cyberprobe_is_interactive_cmd "$1"; then
    __CP_OBS_PENDING_INTERACTIVE=1
  fi
  if [[ -f "$__CP_CAP_OUT" ]]; then
    __CP_CAP_OUT_START=$(wc -c < "$__CP_CAP_OUT" | tr -d ' ')
  else
    __CP_CAP_OUT_START=0
  fi
  if [[ -f "$__CP_CAP_ERR" ]]; then
    __CP_CAP_ERR_START=$(wc -c < "$__CP_CAP_ERR" | tr -d ' ')
  else
    __CP_CAP_ERR_START=0
  fi
}}
__cyberprobe_observe_precmd() {{
  [[ "${{CYBERPROBE_OBSERVE:-0}}" != 1 ]] && return 0
  local rc=$?
  local cmd=""
  local interactive=0
  if [[ -n "${{ZSH_VERSION:-}}" ]]; then
    cmd="${{__CP_OBS_PENDING_CMD:-}}"
    __CP_OBS_PENDING_CMD=""
    [[ "${{__CP_OBS_SKIP_CAPTURE:-0}}" == 1 ]] && return 0
    [[ "${{__CP_OBS_PENDING_INTERACTIVE:-0}}" == 1 ]] && interactive=1
  else
    cmd=$(HISTTIMEFORMAT= history 1 | sed 's/^[[:space:]]*[0-9]*[[:space:]]*//')
    [[ -z "$cmd" ]] && return 0
    if __cyberprobe_observe_skip_capture "$cmd"; then
      __CP_CAP_OUT_START=$(wc -c < "$__CP_CAP_OUT" | tr -d ' ')
      __CP_CAP_ERR_START=$(wc -c < "$__CP_CAP_ERR" | tr -d ' ')
      return 0
    fi
    __cyberprobe_is_interactive_cmd "$cmd" && interactive=1
  fi
  [[ -z "$cmd" ]] && return 0
  if [[ "$interactive" == 1 ]]; then
    __cyberprobe_observe_commit "$cmd" "$rc" 1
  else
    __cyberprobe_observe_commit "$cmd" "$rc" 0
  fi
  if [[ -n "${{BASH_VERSION:-}}" ]]; then
    __CP_CAP_OUT_START=$(wc -c < "$__CP_CAP_OUT" | tr -d ' ')
    __CP_CAP_ERR_START=$(wc -c < "$__CP_CAP_ERR" | tr -d ' ')
  fi
  return 0
}}
__cyberprobe_observe_on() {{
  export CYBERPROBE_OBSERVE=1
  __cyberprobe_observe_enable_tee || return 1
  if [[ -n "${{ZSH_VERSION:-}}" && -z "${{__CP_OBS_HOOKS_ADDED:-}}" ]]; then
    autoload -Uz add-zsh-hook 2>/dev/null
    add-zsh-hook preexec __cyberprobe_observe_preexec 2>/dev/null
    add-zsh-hook precmd __cyberprobe_observe_precmd 2>/dev/null
    __CP_OBS_HOOKS_ADDED=1
    export __CP_OBS_HOOKS_ADDED
  elif [[ -n "${{BASH_VERSION:-}}" && -z "${{__CP_OBS_PROMPT_ADDED:-}}" ]]; then
    __CP_OBS_OLD_PROMPT_COMMAND="${{PROMPT_COMMAND:-}}"
    PROMPT_COMMAND="__cyberprobe_observe_precmd${{PROMPT_COMMAND:+;$PROMPT_COMMAND}}"
    __CP_OBS_PROMPT_ADDED=1
    export __CP_OBS_PROMPT_ADDED
  fi
  printf 'CyberProbe observe: ON\\n'
  printf 'This terminal will remember your last command output for `cyberprobe explain`.\\n'
  printf 'Observe applies only to this shell tab. New tabs start with observe OFF.\\n'
  printf 'Nothing is sent to the AI until you run `cyberprobe explain`.\\n'
}}
__cyberprobe_observe_off() {{
  unset CYBERPROBE_OBSERVE
  printf 'CyberProbe observe: OFF\\n'
}}
__cyberprobe_observe_status() {{
  if [[ "${{CYBERPROBE_OBSERVE:-0}}" == 1 ]]; then
    printf 'CyberProbe observe: ON\\n'
  else
    printf 'CyberProbe observe: OFF\\n'
    printf 'Observe is per shell tab. Open a new Kali/WSL tab? Run `cyberprobe observe on` again.\\n'
  fi
  if [[ -f "${{__CP_OBS_STATE:-}}" ]]; then
    CYBERPROBE_COMPANION=1 python3 {script} --observe-status --observe-state-file "$__CP_OBS_STATE"
  fi
}}
"""

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
{_observe_shell_block()}
cyberprobe() {{
  if [[ "$1" == help ]]; then
    python3 "{COMPANION_SCRIPT}" --local-help
    return 0
  fi
  if [[ "$1" == observe ]]; then
    case "$2" in
      on) __cyberprobe_observe_on ;;
      off) __cyberprobe_observe_off ;;
      status) __cyberprobe_observe_status ;;
      *) printf 'Usage: cyberprobe observe on|off|status\\n' >&2; return 2 ;;
    esac
    return $?
  fi
  if [[ "$1" == explain ]]; then
    CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --explain-observed --observe-state-file "${{__CP_OBS_STATE:-}}"
    return $?
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
{_observe_shell_block()}
cyberprobe() {{
  if [[ "$1" == help ]]; then
    python3 "{COMPANION_SCRIPT}" --local-help
    return 0
  fi
  if [[ "$1" == observe ]]; then
    case "$2" in
      on) __cyberprobe_observe_on ;;
      off) __cyberprobe_observe_off ;;
      status) __cyberprobe_observe_status ;;
      *) printf 'Usage: cyberprobe observe on|off|status\\n' >&2; return 2 ;;
    esac
    return $?
  fi
  if [[ "$1" == explain ]]; then
    CYBERPROBE_COMPANION=1 python3 "{COMPANION_SCRIPT}" --explain-observed --observe-state-file "${{__CP_OBS_STATE:-}}"
    return $?
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
    print("It adds CyberProbe commands, optional observe/explain capture, and natural-language requests.")
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


def _ensure_api_key() -> None:
    if not os.environ.get("GROQ_API_KEY") and API_KEY_FILE.exists():
        saved_key = API_KEY_FILE.read_text(encoding="utf-8").strip()
        if saved_key:
            os.environ["GROQ_API_KEY"] = saved_key


def _chunk_text(text: str, size: int) -> list[str]:
    if not text:
        return [""]
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text) and len(chunks) < OBSERVE_MAX_CHUNKS:
        chunks.append(text[start : start + size])
        start += size
    if start < len(text):
        remaining = len(text) - start
        chunks.append(f"[... {remaining} more characters were not sent to the model ...]")
    return chunks


def write_observe_capture(
    state_file: str,
    command: str,
    returncode: int,
    *,
    stdout: str = "",
    stderr: str = "",
    interactive: bool = False,
) -> int:
    truncated = len(stdout) > MAX_OBSERVE_CAPTURE
    payload = {
        "command": command[:8000],
        "returncode": returncode,
        "stdout": stdout[:MAX_OBSERVE_CAPTURE],
        "stderr": stderr[:20000],
        "interactive": interactive,
        "truncated": truncated,
    }
    if interactive:
        payload["stdout"] = ""
        payload["stderr"] = ""
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return 0


def print_observe_status(state_file: str | None) -> int:
    if not state_file:
        print("No capture yet. Run a command while observe is ON.")
        return 0
    path = Path(state_file)
    if not path.is_file():
        print("No capture yet. Run a command while observe is ON.")
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("No capture yet. Run a command while observe is ON.")
        return 0
    command = (data.get("command") or "").strip()
    if not command:
        print("No capture yet. Run a command while observe is ON.")
        return 0
    if data.get("interactive"):
        print(f"Last: {command} (interactive—not captured)")
        return 0
    stdout = data.get("stdout") or ""
    line_count = len(stdout.splitlines()) if stdout else 0
    extra = "truncated capture" if data.get("truncated") else f"~{line_count} lines stdout"
    print(f"Last captured: {command} (exit {data.get('returncode', '?')}, {extra})")
    print("Tip: run `cyberprobe explain` to translate that output.")
    return 0


def _explain_observed_with_llm(client, command: str, returncode: int, combined: str) -> str:
    chunks = _chunk_text(combined, OBSERVE_CHUNK_SIZE)
    if len(chunks) == 1 and len(combined) <= OBSERVE_CHUNK_SIZE:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": OBSERVE_REDUCE_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "command": command,
                            "returncode": returncode,
                            "output": combined[:MAX_EXPLAIN_OUTPUT],
                        }
                    )[:12000],
                },
            ],
            temperature=0,
        )
        return response.choices[0].message.content or "Could not generate an explanation."

    section_notes: list[str] = []
    total = len(chunks)
    for index, chunk in enumerate(chunks, start=1):
        print(f"[CyberProbe explain {index}/{total}] summarizing output section...", file=sys.stderr)
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": OBSERVE_MAP_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Command: {command}\nReturn code: {returncode}\n"
                        f"Chunk {index} of {total}:\n{chunk[:OBSERVE_CHUNK_SIZE + 500]}"
                    )[:12000],
                },
            ],
            temperature=0,
        )
        section_notes.append(response.choices[0].message.content or "")

    print("[CyberProbe explain] combining sections...", file=sys.stderr)
    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": OBSERVE_REDUCE_PROMPT},
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "command": command,
                        "returncode": returncode,
                        "section_notes": section_notes,
                    }
                )[:12000],
            },
        ],
        temperature=0,
    )
    return response.choices[0].message.content or "Could not generate an explanation."


def explain_observed(state_file: str | None) -> int:
    if not state_file:
        print(
            "\nCyberProbe explain:\n"
            "Run `cyberprobe observe on` in this terminal tab, run your command, then `cyberprobe explain`.\n"
            "Observe is per shell tab—a new Kali/WSL tab starts with observe OFF.\n"
        )
        return 1
    path = Path(state_file)
    if not path.is_file():
        print(
            "\nCyberProbe explain:\n"
            "No captured output yet. Run `cyberprobe observe on`, then run a command, then `cyberprobe explain`.\n"
        )
        return 1
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print("\nCyberProbe explain:\nCould not read the last capture file.\n")
        return 1

    command = (data.get("command") or "").strip()
    if not command:
        print("\nCyberProbe explain:\nNo command has been captured yet.\n")
        return 1
    if data.get("interactive"):
        print(
            f"\nCyberProbe explain:\n"
            f"Last command was interactive—not captured: `{command}`\n"
            "Interactive programs (editors, ssh, msfconsole, etc.) cannot be summarized automatically.\n"
            "Try a non-interactive command, for example `curl -s URL | head`.\n"
        )
        return 1

    stdout = data.get("stdout") or ""
    stderr = data.get("stderr") or ""
    combined = stdout
    if stderr.strip():
        combined = (combined + "\n\n--- stderr ---\n" + stderr).strip()
    if not combined.strip():
        print(
            f"\nCyberProbe explain:\n"
            f"`{command}` returned exit code {data.get('returncode', '?')} with no captured output.\n"
        )
        return 0

    try:
        _ensure_api_key()
        client = get_groq_client()
        explanation = _explain_observed_with_llm(
            client,
            command,
            int(data.get("returncode", 0)),
            combined,
        )
    except Exception as error:
        print(f"\nCyberProbe explain error: {error}\n")
        return 1

    if data.get("truncated"):
        print("\n(Note: very long output was truncated before capture.)\n")
    print("\n[CyberProbe → Output explanation]\n")
    print(explanation)
    print()
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


def _extract_command_path(command: str) -> str:
    try:
        parts = shlex.split(command)
    except ValueError:
        return ""
    for part in reversed(parts):
        if part.startswith("/") or part.startswith("~"):
            return part
    return ""


def _wsl_path_note(path: str) -> str:
    if path.startswith("/mnt/c/Users/"):
        return " Because this is a WSL path, CyberProbe used the Windows user folder mounted inside Kali."
    return ""


def _interpret_command(command: str, returncode: int, stdout: str, stderr: str) -> str:
    stripped = command.strip()
    command_path = _extract_command_path(stripped)
    wsl_note = _wsl_path_note(command_path)
    if returncode != 0:
        detail = stderr.strip().splitlines()[0] if stderr.strip() else "the command returned a non-zero status"
        return f"`{stripped}` did not complete successfully because {detail}."

    if stripped.startswith("ls "):
        files, folders = _parse_ls_listing(stdout)
        pieces = [f"CyberProbe listed the requested folder contents.{wsl_note}"]
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
        target = command_path or (stripped.split(" -- ", 1)[1] if " -- " in stripped else stripped[3:].strip())
        return f"CyberProbe changed your current terminal directory to `{target}`.{wsl_note} This affects the terminal session you are using now."

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
  cyberprobe observe on/off/status        Capture your commands for explain (this tab only)
  cyberprobe explain                      Explain the last captured command output
  cyberprobe auth on/off/status           Allow or block terminal changes
  cyberprobe companion on/off/status      Enable or disable the companion
  cyberprobe analyze this file sample.pdf Send a request to CyberProbe
  cyberprobe go to Documents and list     Propose, ask, then run locally

Learning workflow in your normal terminal:
  cyberprobe observe on
  ping 8.8.8.8
  cyberprobe explain

Observe is OFF in every new shell tab until you turn it on. Nothing is sent to the AI
until you run `cyberprobe explain`. Interactive commands (vim, ssh, msfconsole, etc.)
are not captured.

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
    parser.add_argument("--write-observe-capture", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--observe-status", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--explain-observed", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--observe-state-file", help=argparse.SUPPRESS)
    parser.add_argument("--observe-command", help=argparse.SUPPRESS)
    parser.add_argument("--observe-returncode", type=int, default=0, help=argparse.SUPPRESS)
    parser.add_argument("--observe-stdout-file", help=argparse.SUPPRESS)
    parser.add_argument("--observe-stderr-file", help=argparse.SUPPRESS)
    parser.add_argument("--observe-interactive", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.local_help:
        return print_local_help()
    if args.write_observe_capture:
        if not args.observe_state_file or not args.observe_command:
            return 2
        stdout = _read_limited(args.observe_stdout_file, MAX_OBSERVE_CAPTURE + 1)
        stderr = _read_limited(args.observe_stderr_file, 20001)
        return write_observe_capture(
            args.observe_state_file,
            args.observe_command,
            args.observe_returncode,
            stdout=stdout,
            stderr=stderr,
            interactive=args.observe_interactive,
        )
    if args.observe_status:
        return print_observe_status(args.observe_state_file)
    if args.explain_observed:
        return explain_observed(args.observe_state_file)
    if args.shell_action is not None:
        return print_shell_action(args.shell_action)
    if args.explain_shell_action is not None:
        return explain_shell_action(args.explain_shell_action, args.status_file, args.stdout_file, args.stderr_file)
    if args.request is None:
        parser.error("--request is required")
    return run_request(args.request)


if __name__ == "__main__":
    raise SystemExit(main())
