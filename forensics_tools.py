"""
forensics_tools.py

File forensics domain. Mirrors the pattern in security_tools.py:
- a fixed allowlist of tools/flags (the agent picks a NAME, never raw commands)
- strict input validation (here: file path, not a network target)
- safe subprocess execution with timeouts

This file is the only place that runs forensics commands.
"""

import os
import hashlib
import shutil
import subprocess

# ---------------------------------------------------------------------------
# 1. Allowlisted forensics tools
#    Each entry maps a tool_type name -> fixed command + flags.
#    The agent picks a NAME, never raw flags/commands.
# ---------------------------------------------------------------------------

ALLOWED_TOOLS = {
    "identify_file": {
        "binary": "file",
        "flags": [],
        "description": "Identifies the true file type, regardless of its extension.",
        "typical_seconds": 2,
    },
    "extract_metadata": {
        "binary": "exiftool",
        "flags": [],
        "description": (
            "Extracts hidden metadata (author, GPS location, timestamps, "
            "software used, etc.) embedded in the file."
        ),
        "typical_seconds": 5,
    },
    "hash_file": {
        "binary": "sha256sum",
        "flags": [],
        "description": (
            "Computes a SHA-256 fingerprint of the file. Used to prove the "
            "file hasn't been altered during analysis (integrity check)."
        ),
        "typical_seconds": 2,
    },
    "extract_strings": {
        "binary": "strings",
        "flags": ["-n", "6"],  # only show strings of 6+ printable chars
        "description": (
            "Pulls out readable text hidden inside a binary file -- useful "
            "for spotting URLs, passwords, or messages buried in the data."
        ),
        "typical_seconds": 5,
    },
    "carve_embedded_files": {
        "binary": "binwalk",
        "flags": [],
        "description": (
            "Scans the file for other files or data hidden inside it "
            "(e.g. an image hidden inside a PDF)."
        ),
        "typical_seconds": 15,
    },
    "analyze_memory_image": {
        "binary": "vol",
        "flags": ["-f"],
        "mode": "volatility",
        "plugin": "windows.info",
        "description": (
            "Reads a Windows memory image with Volatility and reports basic "
            "memory-image and operating-system information."
        ),
        "typical_seconds": 30,
    },
    "extract_memory_strings": {
        "binary": "strings",
        "flags": ["-n", "6"],
        "description": (
            "Extracts readable text from a memory image, which can help find "
            "process names, URLs, commands, or other investigation clues."
        ),
        "typical_seconds": 20,
    },
    "inspect_disk_image": {
        "binary": "mmls",
        "flags": [],
        "description": "Examines the partition layout of a disk image without changing it.",
        "typical_seconds": 15,
    },
    "inspect_filesystem_image": {
        "binary": "fsstat",
        "flags": [],
        "description": "Reports filesystem type, metadata, and allocation details from an image.",
        "typical_seconds": 15,
    },
    "list_filesystem_entries": {
        "binary": "fls",
        "flags": ["-r", "-p"],
        "description": "Lists files and directories, including deleted entries when supported.",
        "typical_seconds": 30,
    },
    "carve_data": {
        "binary": "foremost",
        "flags": ["-i"],
        "mode": "output_directory",
        "output_before_input": True,
        "description": "Carves recognizable files from an image into a separate evidence folder.",
        "typical_seconds": 120,
    },
    "recover_deleted_files": {
        "binary": "tsk_recover",
        "flags": ["-a"],
        "mode": "output_directory",
        "description": "Recovers deleted files from a filesystem image into a separate evidence folder.",
        "typical_seconds": 120,
    },
}

MAX_TIMEOUT_SECONDS = 300


# ---------------------------------------------------------------------------
# 2. Input validation / staging
#    Accept any user-provided file path, copy it into a local evidence
#    folder, and work on the copy so the original file is preserved.
# ---------------------------------------------------------------------------

EVIDENCE_DIR = os.path.abspath(os.path.expanduser("~/forensics_evidence"))
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB cap for forensic images


class FileValidationError(Exception):
    pass


def ensure_evidence_dir_exists():
    os.makedirs(EVIDENCE_DIR, exist_ok=True)


def sha256_file(path: str) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def stage_file(file_path: str) -> tuple[str, str]:
    """
    Returns (staged_path, file_hash) for a copied version of the provided
    file inside EVIDENCE_DIR.
    """
    if not file_path or not file_path.strip():
        raise FileValidationError("No file was provided.")

    file_path = file_path.strip()

    # Resolve relative paths against the current working directory so
    # the user can pass a file path directly from where they are working.
    resolved = os.path.realpath(
        file_path if os.path.isabs(file_path) else os.path.join(os.getcwd(), file_path)
    )

    if not os.path.exists(resolved):
        raise FileValidationError(f"File not found: '{file_path}'.")

    if not os.path.isfile(resolved):
        raise FileValidationError(f"'{file_path}' is not a regular file.")

    size = os.path.getsize(resolved)
    if size > MAX_FILE_SIZE_BYTES:
        raise FileValidationError(
            f"File is {size / (1024*1024):.1f} MB, which exceeds the "
            f"{MAX_FILE_SIZE_BYTES / (1024*1024):.0f} MB limit for this MVP."
        )

    ensure_evidence_dir_exists()
    file_hash = sha256_file(resolved)
    base_name = os.path.basename(resolved)
    name, ext = os.path.splitext(base_name)
    staged_name = f"{name}_{file_hash[:12]}{ext}"
    staged_path = os.path.join(EVIDENCE_DIR, staged_name)
    shutil.copy2(resolved, staged_path)

    return staged_path, file_hash


# ---------------------------------------------------------------------------
# 3. Running a forensics tool
# ---------------------------------------------------------------------------

class ForensicsResult:
    def __init__(self, tool_type, original_path, staged_path, file_hash, command, returncode, stdout, stderr, timed_out=False):
        self.tool_type = tool_type
        self.original_path = original_path
        self.staged_path = staged_path
        self.file_hash = file_hash
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out

    @property
    def success(self):
        return self.returncode == 0 and not self.timed_out


def is_tool_installed(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


def _output_directory(staged_path: str, tool_type: str) -> str:
    output_dir = os.path.join(
        EVIDENCE_DIR,
        f"{os.path.basename(staged_path)}_{tool_type}_output",
    )
    os.makedirs(output_dir, exist_ok=True)
    return output_dir


def _build_command(spec: dict, staged_path: str, tool_type: str) -> list[str]:
    command = [spec["binary"]] + spec["flags"]
    mode = spec.get("mode")
    if mode == "volatility":
        return command + [staged_path, spec["plugin"]]
    if mode == "output_directory":
        output_dir = _output_directory(staged_path, tool_type)
        if spec.get("output_before_input"):
            return command + [staged_path, "-o", output_dir]
        return command + [staged_path, output_dir]
    return command + [staged_path]


def run_tool(tool_type: str, file_path: str) -> ForensicsResult:
    """
    Runs an allowlisted forensics tool against a validated file.
    Raises ValueError if tool_type isn't in the allowlist.
    Raises FileValidationError if the file fails validation.
    """
    if tool_type not in ALLOWED_TOOLS:
        raise ValueError(
            f"'{tool_type}' is not an allowed forensics tool. "
            f"Choose one of: {', '.join(ALLOWED_TOOLS.keys())}"
        )

    spec = ALLOWED_TOOLS[tool_type]

    if not is_tool_installed(spec["binary"]):
        return ForensicsResult(
            tool_type=tool_type,
            original_path=file_path,
            staged_path="",
            file_hash="",
            command=f"{spec['binary']} (not installed)",
            returncode=-1,
            stdout="",
            stderr=(
                f"'{spec['binary']}' is not installed on this system. "
                f"Install it and try again."
            ),
        )

    staged_path, file_hash = stage_file(file_path)
    command = _build_command(spec, staged_path, tool_type)

    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=MAX_TIMEOUT_SECONDS,
        )
        return ForensicsResult(
            tool_type=tool_type,
            original_path=file_path,
            staged_path=staged_path,
            file_hash=file_hash,
            command=" ".join(command),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as e:
        return ForensicsResult(
            tool_type=tool_type,
            original_path=file_path,
            staged_path=staged_path,
            file_hash=file_hash,
            command=" ".join(command),
            returncode=-1,
            stdout=e.stdout or "",
            stderr=e.stderr or "",
            timed_out=True,
        )
