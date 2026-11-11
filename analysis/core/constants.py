import re
from datetime import datetime, timezone
from .models import BrowserSpec

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

SKIPPED_USER_DIRS = {
    "public", "default", "default user", "all users",
    "defaultuser0", "desktop.ini"
}

PROFILE_DIR_PATTERN = re.compile(r"^(Default|Profile \d+)$", re.IGNORECASE)
PROFILE_MARKERS = ("prefs.js", "places.sqlite", "times.json", "compatibility.ini")

DOWNLOAD_STATES = {
    0: "In progress", 1: "Complete", 2: "Cancelled",
    3: "Interrupted", 4: "Dangerous"
}

DANGER_TYPES = {
    0: "Not dangerous", 1: "Dangerous file", 2: "Dangerous URL",
    3: "Dangerous content", 4: "Maybe dangerous content", 5: "Uncommon content",
    6: "Dangerous host", 7: "Potentially unwanted", 8: "Allowlisted by policy",
    9: "Pending scan", 10: "Blocked (password protected)", 11: "Blocked (too large)",
    12: "Sensitive content warning", 13: "Sensitive content blocked",
    14: "Deep scanned (safe)", 15: "Deep scanned (opened dangerous)",
    16: "Prompt for scanning", 17: "Blocked (unsupported file type)",
    18: "Account compromise",
}

INTERRUPT_REASONS = {
    0: "None", 1: "File error", 2: "Access denied", 3: "Disk full",
    5: "File too large", 6: "Virus detected", 7: "Transient error", 10: "Blocked",
    11: "Security check failed", 12: "File too short", 13: "Hash mismatch",
    14: "Same as source", 20: "Network failed", 21: "Network timeout",
    22: "Network disconnected", 23: "Server down", 24: "Invalid network request",
    30: "Server failed", 31: "Server does not support range", 32: "Bad server content",
    33: "Server unauthorized", 34: "Server certificate problem", 35: "Server forbidden",
    36: "Server unreachable", 37: "Content length mismatch",
    38: "Cross-origin redirect", 40: "Canceled by user", 41: "Browser shutdown",
    50: "Browser crash",
}

_DOWNLOAD_COLUMNS = (
    "id", "guid", "current_path", "target_path", "start_time", "end_time",
    "received_bytes", "total_bytes", "state", "danger_type", "interrupt_reason",
    "opened", "last_access_time", "referrer", "site_url", "tab_url",
    "tab_referrer_url", "mime_type", "original_mime_type", "etag",
    "last_modified", "http_method", "by_ext_name",
)

FIREFOX_DOWNLOAD_STATES = {
    1: "Complete", 2: "Failed", 3: "Cancelled", 4: "Paused", 5: "Queued",
    6: "Blocked (parental controls)", 7: "Scanning",
    8: "Blocked (malware / reputation)", 9: "Blocked (policy)",
}

CHROME_SPEC = BrowserSpec(
    name="Google Chrome",
    exe_name="chrome.exe",
    system_install_dirs=(
        "Program Files/Google/Chrome/Application",
        "Program Files (x86)/Google/Chrome/Application"
    ),
    per_user_install_dirs=("AppData/Local/Google/Chrome/Application",),
    per_user_data_dir="AppData/Local/Google/Chrome/User Data",
)

FIREFOX_SPEC = BrowserSpec(
    name="Mozilla Firefox",
    exe_name="firefox.exe",
    system_install_dirs=(
        "Program Files/Mozilla Firefox",
        "Program Files (x86)/Mozilla Firefox",
        "Program Files/Mozilla Firefox ESR",
        "Program Files (x86)/Mozilla Firefox ESR",
        "Program Files/Firefox Developer Edition",
        "Program Files (x86)/Firefox Developer Edition",
        "Program Files/Firefox Nightly",
        "Program Files (x86)/Firefox Nightly",
        "Program Files/Mozilla Firefox Beta",
        "Program Files (x86)/Mozilla Firefox Beta"
    ),
    per_user_install_dirs=(
        "AppData/Local/Mozilla Firefox",
        "AppData/Local/Firefox Developer Edition",
        "AppData/Local/Firefox Nightly"
    ),
    per_user_data_dir="AppData/Roaming/Mozilla/Firefox",
)

BRAVE_VENDOR_DIR = "BraveSoftware"
BRAVE_EXE_NAME = "brave.exe"
BRAVE_CHANNELS = (
    "Brave-Browser", "Brave-Browser-Beta", 
    "Brave-Browser-Nightly", "Brave-Browser-Dev"
)