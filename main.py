"""
main.py

CLI entry point. Run with:
    python main.py

Requires:
    pip install -r requirements.txt
"""

import os
import shutil
import subprocess
import sys
import threading
import time
import textwrap
from pathlib import Path

from orchestrator import Orchestrator
from terminal_companion import deploy_companion
from tool_installer import install_tool


CYBERPROBE_BANNER = r"""
    ______      __              ____             __       
  / ____/_  __/ /_  ___  _____/ __ \_________  / /_  ___ 
 / /   / / / / __ \/ _ \/ ___/ /_/ / ___/ __ \/ __ \/ _ \
/ /___/ /_/ / /_/ /  __/ /  / ____/ /  / /_/ / /_/ /  __/
\____/\__, /_.___/\___/_/  /_/   /_/   \____/_.___/\___/ 
     /____/          [ ACCESS GRANTED ]
"""

WELCOME_PANEL = r"""
╔══════════════════════════════════════════════════════════════════╗
║  Learn • Scan • Understand                                       ║
║                                                                  ║
║  CyberProbe helps you explore authorized targets and             ║
║  explains security findings.                                     ║                   
║                                                                  ║
║  Commands:  exit / quit  |  guided on/off                        ║
║                                                                  ║
║  Use CyberProbe only against systems you own or are              ║
║    explicitly authorized to test.                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""


PROMPT = "cyberprobe> "
BOX_WIDTH = 72
API_KEY_FILE = Path.home() / ".cyberprobe_groq_api_key"


def thinking_animation(stop_event):
    frames = ["thinking", "thinking .", "thinking ..", "thinking ..."]
    index = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\rprobe> {frames[index % len(frames)]}".ljust(BOX_WIDTH))
        sys.stdout.flush()
        index += 1
        if stop_event.wait(0.4):
            break
    sys.stdout.write("\r" + " " * BOX_WIDTH + "\r")
    sys.stdout.flush()


def hr(char="="):
    return char * BOX_WIDTH


def wrap_lines(text, width=BOX_WIDTH - 4):
    paragraphs = []
    for raw_para in str(text).splitlines():
        if not raw_para.strip():
            paragraphs.append("")
            continue
        paragraphs.extend(textwrap.wrap(raw_para, width=width) or [""])
    return paragraphs


def format_reply(reply):
    lines = [line.strip() for line in str(reply).strip().splitlines()]
    sections = []
    current_title = None
    current_body = []

    def flush():
        nonlocal current_title, current_body
        if current_title is not None or current_body:
            sections.append((current_title, current_body[:]))
        current_title = None
        current_body = []

    for line in lines:
        normalized = line.rstrip(":").strip().lower()
        if normalized in {
            "summary", "what happened", "what was found", "why it matters",
            "next step", "next steps", "next moves", "recommendation", "recommendations",
        }:
            flush()
            current_title = line.rstrip(":").strip()
            continue
        current_body.append(line)

    flush()

    if not sections:
        sections = [(None, wrap_lines(reply))]

    rendered = [hr("=")]
    rendered.append("probe> CYBERPROBE RESPONSE")
    rendered.append(hr("-"))
    for title, body in sections:
        if title:
            rendered.append(f"[ {title.upper()} ]")
        body_text = "\n".join(body).strip()
        if body_text:
            for wrapped in wrap_lines(body_text):
                rendered.append(f"  {wrapped}" if wrapped else "")
        rendered.append("")
    rendered.append(hr("="))
    return "\n".join(rendered).rstrip()


def print_intro():
    os.system("cls" if os.name == "nt" else "clear")
    print("\n" + CYBERPROBE_BANNER)
    print(WELCOME_PANEL)
    print("Booting secure console...\n")


def print_help():
    print("""CyberProbe commands:
  help                         Show this help
  status                       Show connection and agent status
  check setup                 List installed and missing tools
  install TOOL                Install an approved tool (asks first)
  deploy terminal companion   Enable requests from Bash/Zsh terminals
  companion on/off/status     Enable, disable, or check the companion
  auth on/off/status          Allow or block terminal changes
  observe on/off/status       Capture terminal output for explain (companion shell)
  explain                     Explain last captured output (companion shell)
  change_key                  Replace the saved Groq API key
  reset_key                   Remove the saved Groq API key
  guided on/off               Toggle suggested next steps
  exit                        Close CyberProbe

Terminal companion examples:
  $ cyberprobe analyze this file sample.pdf
  $ analyze this file sample.pdf
  $ cyberprobe observe on
  $ ping 8.8.8.8
  $ cyberprobe explain
  $ cyberprobe auth on
  $ cyberprobe create a folder called games on Desktop
  $ cyberprobe auth off

Agent examples:
  show listening ports
  scan 127.0.0.1
  investigate this Linux host for suspicious activity
  check the headers at http://localhost:8080
  analyze this file /path/to/evidence.bin
  create a prioritized security report
""")


def print_setup_status():
    tools = (
        "nmap", "curl", "gobuster", "ffuf", "subfinder", "whatweb",
        "arp-scan", "dig", "host", "nslookup", "nc", "nuclei", "lynis",
        "ufw", "nft", "tcpdump", "journalctl", "lastb", "auditctl",
        "systemctl", "ss", "sha256sum", "stat", "vol", "mmls", "fsstat",
        "fls", "foremost", "tsk_recover",
    )
    print("\nLocal tool status:")
    for tool in tools:
        print(f"  {'available' if shutil.which(tool) else 'missing  '}  {tool}")
    print("\nMissing tools are only needed for the capabilities that use them.\n")


def print_status():
    key_state = "configured" if os.environ.get("GROQ_API_KEY") or load_saved_api_key() else "not configured"
    print(f"\nGroq API key: {key_state}")
    print("Agents: Recon, Forensics, Linux System, Terminal Operations, Defensive Security, Web Security, Network Security, Vulnerability Assessment\n")


def friendly_error(error):
    message = str(error)
    if "Could not connect" in message or "Failed to connect" in message:
        return "No web service responded at that address. Check the URL and port, then try again."
    if "Operation not permitted" in message or "Permission denied" in message:
        return "Linux denied this inspection. Try running CyberProbe with the required permissions on your own machine."
    if "not installed" in message or "No such file" in message:
        return f"A required tool is missing. Run `install TOOL` after `check setup`. Details: {message}"
    return message


def load_saved_api_key():
    if not API_KEY_FILE.exists():
        return None
    try:
        key = API_KEY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return key or None


def save_api_key(api_key: str):
    API_KEY_FILE.write_text(api_key.strip() + "\n", encoding="utf-8")
    try:
        os.chmod(API_KEY_FILE, 0o600)
    except OSError:
        pass


def ensure_api_key():
    api_key = os.environ.get("GROQ_API_KEY")
    if api_key:
        return api_key.strip()

    saved_key = load_saved_api_key()
    if saved_key:
        os.environ["GROQ_API_KEY"] = saved_key
        return saved_key

    print("No saved Groq API key was found.")
    print(f"Paste your key once and it will be saved to {API_KEY_FILE} for next time.")
    api_key = input("GROQ API key: ").strip()
    if not api_key:
        return None

    save_api_key(api_key)
    os.environ["GROQ_API_KEY"] = api_key
    return api_key


def set_api_key(api_key: str):
    api_key = api_key.strip()
    if not api_key:
        raise ValueError("No API key was provided.")
    save_api_key(api_key)
    os.environ["GROQ_API_KEY"] = api_key


def delete_saved_api_key():
    try:
        API_KEY_FILE.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass
    os.environ.pop("GROQ_API_KEY", None)


def is_change_key_command(user_input: str) -> bool:
    lowered = user_input.lower()
    return lowered == "change_key" or lowered.startswith("change_key ") or lowered == "chnage_key" or lowered.startswith("chnage_key ")


def extract_key_from_command(user_input: str) -> str | None:
    lowered = user_input.lower()
    if lowered in ("change_key", "chnage_key"):
        return None
    if lowered.startswith("change_key "):
        return user_input.split(" ", 1)[1].strip()
    if lowered.startswith("chnage_key "):
        return user_input.split(" ", 1)[1].strip()
    return None


def install_command_tool(user_input: str) -> str | None:
    parts = user_input.split()
    if len(parts) != 2 or parts[0].lower() != "install":
        return None
    tool = parts[1].lower()
    try:
        result = install_tool(tool)
    except (RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        return f"Installation error: {error}"
    return result["message"]


def run_agent_turn(agent: Orchestrator, user_input: str) -> str:
    stop_event = threading.Event()
    spinner = threading.Thread(target=thinking_animation, args=(stop_event,), daemon=True)
    spinner.start()
    try:
        return agent.send(user_input)
    finally:
        stop_event.set()
        spinner.join()


def guided_follow_up_loop(agent: Orchestrator) -> None:
    """Let the beginner pick a numbered next move until they skip."""
    while True:
        menu = agent.get_suggestions_menu()
        if not menu:
            break
        print(menu)
        try:
            choice = input("next> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        follow_up = agent.resolve_follow_up(choice)
        if follow_up is None:
            break
        try:
            reply = run_agent_turn(agent, follow_up)
        except Exception as error:
            print(f"\n[error] {friendly_error(error)}\n")
            break
        print("\n" + format_reply(reply) + "\n")


def main():
    print_intro()
    if not ensure_api_key():
        print("Setup error: no Groq API key was provided.")
        return
    try:
        agent = Orchestrator()
    except RuntimeError as e:
        print(f"Setup error: {e}")
        return

    guided_mode = True
    print("Connection ready. Guided mode is ON — CyberProbe will suggest next steps after each scan.")
    print("Type `guided off` to disable. What do you want to investigate?\n")

    while True:
        try:
            user_input = input(PROMPT).strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print("Goodbye.")
            break
        if user_input.lower() == "guided on":
            guided_mode = True
            print("\nGuided mode enabled.\n")
            continue
        if user_input.lower() == "guided off":
            guided_mode = False
            print("\nGuided mode disabled.\n")
            continue
        if user_input.lower() == "help":
            print_help()
            continue
        if user_input.lower() == "status":
            print_status()
            continue
        if user_input.lower() in ("check setup", "check_setup"):
            print_setup_status()
            continue
        if user_input.lower().startswith("install "):
            result = install_command_tool(user_input)
            if result is None:
                print("\nUsage: install TOOL\n")
            else:
                print(f"\n{result}\n")
            continue
        if user_input.lower() in {"deploy terminal companion", "deploy companion"}:
            print(f"\n{deploy_companion()}\n")
            continue
        if user_input.lower() in {"auth on", "auth off", "auth status"}:
            auth_command = user_input.lower().split()[1]
            if auth_command == "on":
                os.environ["CYBERPROBE_AUTH"] = "1"
            elif auth_command == "off":
                os.environ.pop("CYBERPROBE_AUTH", None)
            state = "ON" if os.environ.get("CYBERPROBE_AUTH") == "1" else "OFF"
            print(f"\nCyberProbe terminal authorization: {state}\n")
            continue
        if user_input.lower() in {"observe on", "observe off", "observe status"}:
            print(
                "\nObserve and explain run in your Bash/Zsh terminal after "
                "`deploy terminal companion`.\n"
                "In that terminal use: cyberprobe observe on → run a command → cyberprobe explain\n"
            )
            continue
        if user_input.lower() == "explain":
            print(
                "\n`explain` works in your Bash/Zsh terminal after `cyberprobe observe on` "
                "and a captured command.\nUse: cyberprobe explain\n"
            )
            continue
        if user_input.lower() in {"companion on", "companion off", "companion status"}:
            companion_command = user_input.lower().split()[1]
            if companion_command == "on":
                os.environ.pop("CYBERPROBE_COMPANION_DISABLED", None)
            elif companion_command == "off":
                os.environ["CYBERPROBE_COMPANION_DISABLED"] = "1"
            state = "OFF" if os.environ.get("CYBERPROBE_COMPANION_DISABLED") == "1" else "ON"
            print(f"\nCyberProbe terminal companion: {state}\n")
            continue
        if is_change_key_command(user_input):
            new_key = extract_key_from_command(user_input)
            if new_key is None:
                new_key = input("Paste the new Groq API key: ").strip()
            try:
                set_api_key(new_key)
            except ValueError as e:
                print(f"\n[error] {e}\n")
                continue
            print("\nGroq API key updated and saved.\n")
            continue
        if user_input.lower() == "reset_key":
            delete_saved_api_key()
            print("\nSaved Groq API key removed. Restart the app or run `change_key`.\n")
            continue

        try:
            reply = run_agent_turn(agent, user_input)
        except Exception as e:
            print(f"\n[error] {friendly_error(e)}\n")
            continue

        print("\n" + format_reply(reply) + "\n")
        if guided_mode:
            guided_follow_up_loop(agent)


if __name__ == "__main__":
    main()
