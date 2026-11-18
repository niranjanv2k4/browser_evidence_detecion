import atexit
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def cleanup_brave_extracted_files() -> None:
    """
    Deletes BraveData.json and DllExtractChromiumSecrets.dll created by DumpBrowserSecrets.exe.
    """
    extractor_dir = Path(__file__).resolve().parent / "brave"
    for filename in ("BraveData.json", "DllExtractChromiumSecrets.dll"):
        file_path = extractor_dir / filename
        if file_path.is_file():
            try:
                os.remove(file_path)
            except OSError:
                pass


# Automatically register cleanup on process exit
atexit.register(cleanup_brave_extracted_files)


def extract_brave_passwords(log_callback: Optional[Callable[[str], None]] = None) -> List[Dict[str, str]]:
    """
    Executes DumpBrowserSecrets.exe /b:brave to dump Brave stored credentials,
    reads BraveData.json, and extracts only the relevant fields:
    [{"hostname": ..., "username": ..., "password": ...}, ...]
    """
    extractor_dir = Path(__file__).resolve().parent / "brave"
    exe_path = extractor_dir / "DumpBrowserSecrets.exe"
    json_path = extractor_dir / "BraveData.json"

    if not exe_path.is_file():
        if log_callback:
            log_callback(f"DumpBrowserSecrets.exe not found at {exe_path}")
        return []

    try:
        # Clean up any leftover files before running
        cleanup_brave_extracted_files()

        if log_callback:
            log_callback("Running DumpBrowserSecrets.exe to extract Brave passwords...")

        cmd = [str(exe_path), "/b:brave", "/e:all"]
        result = subprocess.run(
            cmd,
            cwd=str(extractor_dir),
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

        if log_callback and result.stdout:
            for line in result.stdout.splitlines():
                line_str = line.strip()
                if line_str.startswith(("[+]", "[i] Logins:", "[!]", "[*]")):
                    log_callback(line_str)

    except subprocess.TimeoutExpired:
        if log_callback:
            log_callback("DumpBrowserSecrets.exe timed out after 30 seconds.")
    except Exception as exc:
        if log_callback:
            log_callback(f"Error executing DumpBrowserSecrets.exe: {exc}")

    if not json_path.is_file():
        if log_callback:
            log_callback(f"BraveData.json not found at {json_path}")
        return []

    try:
        # Use utf-8-sig to automatically handle potential UTF-8 BOM emitted by the tool
        with open(json_path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)

        raw_logins = data.get("logins", [])
        extracted = []
        for entry in raw_logins:
            hostname = entry.get("origin_url") or entry.get("action_url") or ""
            username = entry.get("username") or ""
            password = entry.get("password") or ""

            if hostname or username or password:
                extracted.append({
                    "hostname": hostname,
                    "username": username,
                    "password": password,
                })

        if log_callback:
            log_callback(f"Successfully extracted {len(extracted)} saved password(s) from Brave.")
        return extracted

    except Exception as exc:
        if log_callback:
            log_callback(f"Error reading or parsing BraveData.json: {exc}")
        return []

