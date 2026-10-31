"""
firefox_analyzer.py  --  standalone Mozilla Firefox analysis engine (per installation).

Same calling convention as chrome_analyzer.py. No GUI code, no drive detection,
no browser detection. Your GUI calls ONE function:

    from firefox_analyzer import analyze_firefox

    result = analyze_firefox(selected_drive, selected_browser, target_exe_path,
                             log_callback=None, options=None)

    selected_drive   : e.g. "D:\\"
    selected_browser : e.g. "Mozilla Firefox"  (also accepts "Firefox",
                       "Firefox ESR", "Firefox Developer Edition", "Firefox Nightly")
    target_exe_path  : full path of the EXACT firefox.exe to analyse,
                       e.g. "D:\\Program Files\\Mozilla Firefox\\firefox.exe"
    log_callback     : optional function(str) receiving each log line live
    options          : optional AnalysisOptions (what to collect)

It returns an AnalysisResult (use result.to_dict() for a plain dict) and never raises.

WHAT "PER INSTALLATION" MEANS HERE
  Only profiles/activity that belong to the installation in target_exe_path are
  reported under result.profiles. Two installs on one drive give two separate
  results. A profile is tied to an installation by, in order of strength:

    1. CONFIRMED  profiles.ini / installs.ini has an [Install<HASH>] entry whose HASH
                  is Firefox's install hash (CityHash64 of the UTF-16 install
                  directory path) of THIS installation -> its Default= profile.
    2. CONFIRMED  portable/adjacent profile folder next to the exe
                  (e.g. PortableApps: ..\\Data\\profile).
    3. INFERRED   compatibility.ini in the profile names this installation's
                  directory as the last one that used it (LastPlatformDir/LastAppDir).
    4. INFERRED   no [Install...] entry matches this installation and the profile is
                  the legacy default (Default=1) -- what Firefox itself would use.
    Everything else is "unattributed": listed in result.unattributed_profiles with
    metadata only, and analysed ONLY if options.include_unattributed is True
    (still kept separate from result.profiles).

  Forensic note: the install hash depends on the drive letter the original system
  used. For a mounted image the letter differs, so the hash is computed for the
  install path under every drive letter A-Z. A match under the selected drive's own
  letter is "exact"; any other letter is reported as "drive-letter substituted".

Forensic handling (same as the Chrome analyzer):
  * Paths derive from selected_drive; the live registry/environment are NOT used.
    Absolute paths found inside profiles.ini are re-mapped onto selected_drive so a
    mounted image never resolves to the live system's files.
  * Read-only: every SQLite database is copied (with its -wal / -journal) to a temp
    folder and the COPY is queried, then deleted. Firefox uses WAL for
    places.sqlite, so recent activity lives in the -wal file; it is copied too.
    If copying fails, a read-only "immutable" open is tried (WAL is then ignored
    and a warning is logged). SHA-256 of each analysed copy is recorded.
  * Nothing is written to the source drive. Firefox is never launched.
  * Cookie VALUES, saved passwords and form-history values are never decrypted
    or exported as secrets (cookie values are not read at all; logins are not read).
  * A missing artifact is reported as unavailable, never as proof of non-use.
"""

import configparser
import ctypes
import hashlib
import json
import os
import re
import shutil
import sqlite3
import string
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ================================================================== models
@dataclass(frozen=True)
class BrowserSpec:
    """Where Firefox-family installs / data live, relative to a drive root."""
    name: str
    exe_name: str
    system_install_dirs: tuple      # relative to drive root
    per_user_install_dirs: tuple    # relative to Users\<user>
    per_user_data_dir: str          # relative to Users\<user>  (profiles.ini lives here)


@dataclass
class AnalysisOptions:
    include_inferred: bool = True          # analyse "inferred" profiles (reported as inferred)
    include_unattributed: bool = False     # analyse profiles NOT tied to this installation
    collect_bookmarks: bool = True
    collect_downloads: bool = True
    collect_form_history: bool = True
    collect_cookies: bool = True           # metadata only, never values
    collect_extensions: bool = True


@dataclass
class BrowserInfo:
    name: str
    edition: Optional[str] = None           # application.ini [App] Name
    vendor: Optional[str] = None
    version: Optional[str] = None
    version_source: Optional[str] = None
    build_id: Optional[str] = None
    update_channel: Optional[str] = None
    executable_path: Optional[str] = None
    executable_sha256: Optional[str] = None
    executable_exists: bool = False
    installation_path: Optional[str] = None
    install_path_for_hash: Optional[str] = None     # drive-relative path used for hashing
    install_hash_candidates: Dict[str, str] = field(default_factory=dict)  # letter -> HASH
    matched_install_hash: Optional[str] = None
    install_hash_match_kind: Optional[str] = None   # "exact" | "drive-letter substituted"
    user_data_paths: List[str] = field(default_factory=list)   # Mozilla\Firefox roots examined
    notes: List[str] = field(default_factory=list)


@dataclass
class HistoryRecord:
    url: str
    title: str
    visit_time: Optional[str]      # last visit of this URL, UTC
    visit_count: int
    typed: int
    hidden: int
    profile: str


@dataclass
class BookmarkRecord:
    title: str
    url: str
    folder: str
    date_added: Optional[str]
    last_modified: Optional[str]
    profile: str


@dataclass
class DownloadRecord:
    source_url: str
    target_path: Optional[str]
    state: Optional[str]
    end_time: Optional[str]
    file_size: Optional[int]
    profile: str


@dataclass
class FormHistoryRecord:
    field_name: str
    value: str
    times_used: int
    first_used: Optional[str]
    last_used: Optional[str]
    profile: str


@dataclass
class CookieRecord:                  # metadata only -- value is deliberately not read
    host: str
    name: str
    path: str
    created: Optional[str]
    last_accessed: Optional[str]
    expiry: Optional[str]
    secure: bool
    http_only: bool
    profile: str


@dataclass
class ExtensionRecord:
    addon_id: str
    name: Optional[str]
    version: Optional[str]
    addon_type: Optional[str]
    location: Optional[str]
    active: Optional[bool]
    installed: Optional[str]
    updated: Optional[str]
    profile: str


@dataclass
class HistoryStatistics:
    history_record_count: int = 0     # rows in moz_places that were actually visited
    total_visits: int = 0             # sum of visit_count over those rows
    visit_row_count: int = 0          # rows in moz_historyvisits
    unvisited_place_count: int = 0    # moz_places rows with no visits (e.g. bookmark-only)
    unique_url_count: int = 0
    unique_domain_count: int = 0
    typed_url_count: int = 0
    first_visit: Optional[str] = None
    last_visit: Optional[str] = None


@dataclass
class ProfileResult:
    directory_name: str
    path: str
    windows_user: str
    attribution: str = "unattributed"          # confirmed | inferred | unattributed
    attribution_basis: str = ""
    display_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # per-database status + hashes
    history_db_path: Optional[str] = None
    history_status: str = "Not analyzed"
    history_db_sha256: Optional[str] = None
    history: List[HistoryRecord] = field(default_factory=list)
    statistics: HistoryStatistics = field(default_factory=HistoryStatistics)
    bookmarks: List[BookmarkRecord] = field(default_factory=list)
    downloads: List[DownloadRecord] = field(default_factory=list)
    form_history: List[FormHistoryRecord] = field(default_factory=list)
    cookies: List[CookieRecord] = field(default_factory=list)
    extensions: List[ExtensionRecord] = field(default_factory=list)


@dataclass
class AnalysisResult:
    drive: str
    browser: Optional[BrowserInfo] = None
    profiles: List[ProfileResult] = field(default_factory=list)               # THIS installation only
    unattributed_profiles: List[ProfileResult] = field(default_factory=list)  # found, not tied to it
    summary: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    started_utc: Optional[str] = None
    finished_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ================================================================== utilities
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def format_utc(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None


def _unix_to_string(value: Any, unit: str) -> Optional[str]:
    """unit: 'us' | 'ms' | 's'. Returns None for 0/negative/invalid/out-of-range."""
    try:
        number = int(value)
        if number <= 0:
            return None
        delta = {"us": timedelta(microseconds=number),
                 "ms": timedelta(milliseconds=number),
                 "s": timedelta(seconds=number)}[unit]
        return format_utc(UNIX_EPOCH + delta)
    except (TypeError, ValueError, OverflowError):
        return None


def firefox_time_to_string(value: Any) -> Optional[str]:
    """Firefox places/formhistory/cookies: microseconds since 1970-01-01 UTC."""
    return _unix_to_string(value, "us")


def millis_to_string(value: Any) -> Optional[str]:
    return _unix_to_string(value, "ms")


def now_utc_string() -> str:
    return format_utc(datetime.now(timezone.utc))


class AnalysisLogger:
    """Collects timestamped log lines and forwards each to an optional callback."""

    def __init__(self, callback: Optional[Callable[[str], None]] = None):
        self.entries: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
        self._callback = callback

    def _emit(self, prefix: str, message: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {prefix}{message}"
        self.entries.append(line)
        if self._callback:
            try:
                self._callback(line)
            except Exception:
                pass  # a broken GUI callback must never break the analysis

    def info(self, message: str) -> None:
        self._emit("", message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)
        self._emit("WARNING: ", message)

    def error(self, message: str) -> None:
        self.errors.append(message)
        self._emit("ERROR: ", message)


def read_json_file(path: str) -> Tuple[Optional[Any], Optional[str]]:
    if not os.path.isfile(path):
        return None, "file not found"
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            return json.load(handle), None
    except PermissionError:
        return None, "permission denied"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON ({exc})"
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"cannot be read ({exc})"


def read_text_file(path: str) -> Tuple[Optional[str], Optional[str]]:
    if not os.path.isfile(path):
        return None, "file not found"
    last_error = "cannot be read"
    for encoding in ("utf-8-sig", "cp1252"):
        try:
            with open(path, "r", encoding=encoding) as handle:
                return handle.read(), None
        except UnicodeDecodeError as exc:
            last_error = str(exc)
        except PermissionError:
            return None, "permission denied"
        except OSError as exc:
            return None, f"cannot be read ({exc})"
    return None, last_error


def read_ini(path: str) -> Tuple[Optional[configparser.RawConfigParser], Optional[str]]:
    text, error = read_text_file(path)
    if error:
        return None, error
    parser = configparser.RawConfigParser(strict=False, delimiters=("=",), interpolation=None)
    parser.optionxform = str  # keep key case
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        return None, f"invalid INI ({exc})"
    return parser, None


def file_metadata(path: str) -> Optional[Dict[str, Any]]:
    try:
        st = os.stat(path)
    except OSError:
        return None

    def utc(ts: float) -> Optional[str]:
        try:
            return format_utc(datetime.fromtimestamp(ts, tz=timezone.utc))
        except (OverflowError, OSError, ValueError):
            return None

    return {"size_bytes": st.st_size, "modified_utc": utc(st.st_mtime),
            "created_utc": utc(st.st_ctime)}


def sha256_file(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def dig(data: Any, *keys: str) -> Any:
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def get_domain(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


def get_file_version(path: str) -> Optional[str]:
    """Version resource of an .exe (Windows only). Reads the file; never runs it."""
    if sys.platform != "win32":
        return None
    try:
        class VS_FIXEDFILEINFO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in (
                "dwSignature", "dwStrucVersion", "dwFileVersionMS", "dwFileVersionLS",
                "dwProductVersionMS", "dwProductVersionLS", "dwFileFlagsMask",
                "dwFileFlags", "dwFileOS", "dwFileType", "dwFileSubtype",
                "dwFileDateMS", "dwFileDateLS")]

        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
        version.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
        version.GetFileVersionInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                                ctypes.c_uint32, ctypes.c_void_p]
        version.GetFileVersionInfoW.restype = ctypes.c_int
        version.VerQueryValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_uint)]
        version.VerQueryValueW.restype = ctypes.c_int
        size = version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buffer = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, buffer):
            return None
        pointer = ctypes.c_void_p()
        length = ctypes.c_uint()
        if not version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return None
        info = VS_FIXEDFILEINFO.from_address(pointer.value)
        if info.dwSignature != 0xFEEF04BD:
            return None
        ms, ls = info.dwFileVersionMS, info.dwFileVersionLS
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        return None


# ============================================================ install hash
# Firefox names the [Install<HASH>] section in profiles.ini after
# CityHash64(<install directory as UTF-16LE>), printed as upper-case hex.
# (CityHash v1.0.x. Verified: "C:\Program Files\Mozilla Firefox" -> 308046B0AF4A39CB.)
_M64 = (1 << 64) - 1
_K0, _K1, _K2, _K3 = 0xc3a5c85c97cb3127, 0xb492b66fbe98f273, 0x9ae16a3b2f90404f, 0xc949d7c7509e6557


def _rot(v: int, s: int) -> int:
    return v if s == 0 else ((v >> s) | (v << (64 - s))) & _M64


def _shift_mix(v: int) -> int:
    return v ^ (v >> 47)


def _f64(b: bytes, i: int) -> int:
    return int.from_bytes(b[i:i + 8], "little")


def _f32(b: bytes, i: int) -> int:
    return int.from_bytes(b[i:i + 4], "little")


def _hash_len16(u: int, v: int) -> int:
    mul = 0x9ddfea08eb382d69
    a = ((u ^ v) * mul) & _M64
    a ^= a >> 47
    b = ((v ^ a) * mul) & _M64
    b ^= b >> 47
    return (b * mul) & _M64


def _weak32(w: int, x: int, y: int, z: int, a: int, b: int) -> Tuple[int, int]:
    a = (a + w) & _M64
    b = _rot((b + a + z) & _M64, 21)
    c = a
    a = (a + x + y) & _M64
    b = (b + _rot(a, 44)) & _M64
    return (a + z) & _M64, (b + c) & _M64


def _weak32_s(s: bytes, i: int, a: int, b: int) -> Tuple[int, int]:
    return _weak32(_f64(s, i), _f64(s, i + 8), _f64(s, i + 16), _f64(s, i + 24), a, b)


def _len0to16(s: bytes, n: int) -> int:
    if n > 8:
        a, b = _f64(s, 0), _f64(s, n - 8)
        return _hash_len16(a, _rot((b + n) & _M64, n)) ^ b
    if n >= 4:
        return _hash_len16((n + (_f32(s, 0) << 3)) & _M64, _f32(s, n - 4))
    if n > 0:
        a, b, c = s[0], s[n >> 1], s[n - 1]
        y = (a + (b << 8)) & 0xFFFFFFFF
        z = (n + (c << 2)) & 0xFFFFFFFF
        return (_shift_mix(((y * _K2) & _M64) ^ ((z * _K3) & _M64)) * _K2) & _M64
    return _K2


def _len17to32(s: bytes, n: int) -> int:
    a = (_f64(s, 0) * _K1) & _M64
    b = _f64(s, 8)
    c = (_f64(s, n - 8) * _K2) & _M64
    d = (_f64(s, n - 16) * _K0) & _M64
    return _hash_len16((_rot((a - b) & _M64, 43) + _rot(c, 30) + d) & _M64,
                       (a + _rot(b ^ _K3, 20) - c + n) & _M64)


def _len33to64(s: bytes, n: int) -> int:
    z = _f64(s, 24)
    a = (_f64(s, 0) + (n + _f64(s, n - 16)) * _K0) & _M64
    b = _rot((a + z) & _M64, 52)
    c = _rot(a, 37)
    a = (a + _f64(s, 8)) & _M64
    c = (c + _rot(a, 7)) & _M64
    a = (a + _f64(s, 16)) & _M64
    vf, vs = (a + z) & _M64, (b + _rot(a, 31) + c) & _M64
    a = (_f64(s, 16) + _f64(s, n - 32)) & _M64
    z = _f64(s, n - 8)
    b = _rot((a + z) & _M64, 52)
    c = _rot(a, 37)
    a = (a + _f64(s, n - 24)) & _M64
    c = (c + _rot(a, 7)) & _M64
    a = (a + _f64(s, n - 16)) & _M64
    wf, ws = (a + z) & _M64, (b + _rot(a, 31) + c) & _M64
    r = _shift_mix((((vf + ws) & _M64) * _K2 + ((wf + vs) & _M64) * _K0) & _M64)
    return (_shift_mix((r * _K0 + vs) & _M64) * _K2) & _M64


def city_hash64(data: bytes) -> int:
    n = len(data)
    if n <= 32:
        return _len0to16(data, n) if n <= 16 else _len17to32(data, n)
    if n <= 64:
        return _len33to64(data, n)
    x = _f64(data, n - 40)
    y = (_f64(data, n - 16) + _f64(data, n - 56)) & _M64
    z = _hash_len16((_f64(data, n - 48) + n) & _M64, _f64(data, n - 24))
    v = _weak32_s(data, n - 64, n, z)
    w = _weak32_s(data, n - 32, (y + _K1) & _M64, x)
    x = (x * _K1 + _f64(data, 0)) & _M64
    remaining = (n - 1) & ~63
    i = 0
    while True:
        x = (_rot((x + y + v[0] + _f64(data, i + 8)) & _M64, 37) * _K1) & _M64
        y = (_rot((y + v[1] + _f64(data, i + 48)) & _M64, 42) * _K1) & _M64
        x ^= w[1]
        y = (y + v[0] + _f64(data, i + 40)) & _M64
        z = (_rot((z + w[0]) & _M64, 33) * _K1) & _M64
        v = _weak32_s(data, i, (v[1] * _K1) & _M64, (x + w[0]) & _M64)
        w = _weak32_s(data, i + 32, (z + y) & _M64, (y + _f64(data, i + 16)) & _M64)
        z, x = x, z
        i += 64
        remaining -= 64
        if remaining == 0:
            break
    return _hash_len16((_hash_len16(v[0], w[0]) + _shift_mix(y) * _K1 + z) & _M64,
                       (_hash_len16(v[1], w[1]) + x) & _M64)


def firefox_install_hash(windows_install_dir: str) -> str:
    """Install hash for a Windows install directory such as
    'C:\\Program Files\\Mozilla Firefox' (no trailing backslash)."""
    return "%016X" % city_hash64(windows_install_dir.encode("utf-16-le"))


def compute_install_hash_candidates(install_dir: str, root_drive: str
                                    ) -> Tuple[Optional[str], Dict[str, str], Optional[str]]:
    """Return (drive_relative_path, {letter: HASH}, exact_letter).

    The path is taken relative to the selected drive and prefixed with every drive
    letter, because the letter on the ORIGINAL system is unknown for a mounted image."""
    drive_letter = None
    match = re.match(r"^([A-Za-z]):", root_drive or "")
    if match:
        drive_letter = match.group(1).upper()
    try:
        relative = os.path.relpath(install_dir, root_drive)
    except ValueError:
        relative = None
    if relative is None or relative.startswith(".."):
        # install lies outside the selected drive: use the path as given
        given = str(PureWindowsPath(install_dir))
        m = re.match(r"^([A-Za-z]):\\(.*)$", given)
        if not m:
            return None, {}, drive_letter
        relative = m.group(2)
        drive_letter = m.group(1).upper()
    relative = str(PureWindowsPath(relative)).rstrip("\\")
    candidates = {letter: firefox_install_hash(f"{letter}:\\{relative}")
                  for letter in string.ascii_uppercase}
    return relative, candidates, drive_letter


# ============================================================ browser specs
FIREFOX_SPEC = BrowserSpec(
    name="Mozilla Firefox",
    exe_name="firefox.exe",
    system_install_dirs=("Program Files/Mozilla Firefox",
                         "Program Files (x86)/Mozilla Firefox",
                         "Program Files/Mozilla Firefox ESR",
                         "Program Files (x86)/Mozilla Firefox ESR",
                         "Program Files/Firefox Developer Edition",
                         "Program Files (x86)/Firefox Developer Edition",
                         "Program Files/Firefox Nightly",
                         "Program Files (x86)/Firefox Nightly",
                         "Program Files/Mozilla Firefox Beta",
                         "Program Files (x86)/Mozilla Firefox Beta"),
    per_user_install_dirs=("AppData/Local/Mozilla Firefox",
                           "AppData/Local/Firefox Developer Edition",
                           "AppData/Local/Firefox Nightly"),
    per_user_data_dir="AppData/Roaming/Mozilla/Firefox",
)

SUPPORTED_BROWSER_NAMES = {"mozilla firefox", "firefox", "firefox esr", "firefox developer edition",
                           "firefox nightly", "firefox beta", "mozilla firefox esr"}

SKIPPED_USER_DIRS = {"public", "default", "default user", "all users",
                     "defaultuser0", "desktop.ini"}

PROFILE_MARKERS = ("prefs.js", "places.sqlite", "times.json", "compatibility.ini")


class DatabaseAccessError(Exception):
    """A SQLite database could not be read (locked, corrupt, ...)."""


# ============================================================ locating
def _list_windows_users(root_drive: str, logger: AnalysisLogger) -> List[str]:
    users_dir = os.path.join(root_drive, "Users")
    users: List[str] = []
    try:
        with os.scandir(users_dir) as entries:
            for entry in entries:
                if entry.name.lower() in SKIPPED_USER_DIRS:
                    continue
                try:
                    if entry.is_dir():
                        users.append(entry.name)
                except OSError:
                    logger.warning(f"Cannot inspect {entry.path}")
    except FileNotFoundError:
        logger.warning(f"No 'Users' folder on {root_drive} (not a Windows system volume?).")
    except OSError as exc:
        logger.warning(f"Unable to read {users_dir}: {exc}")
    return sorted(users)


def discover_firefox_installations(root_drive: str,
                                   logger: Optional[AnalysisLogger] = None) -> List[str]:
    """List firefox.exe paths found in standard locations (for a GUI dropdown).
    Each one is an independent installation; analyse them one by one."""
    logger = logger or AnalysisLogger()
    found: List[str] = []
    for relative in FIREFOX_SPEC.system_install_dirs:
        candidate = os.path.normpath(os.path.join(root_drive, relative, FIREFOX_SPEC.exe_name))
        if os.path.isfile(candidate):
            found.append(candidate)
    for user in _list_windows_users(root_drive, logger):
        for relative in FIREFOX_SPEC.per_user_install_dirs:
            candidate = os.path.normpath(
                os.path.join(root_drive, "Users", user, relative, FIREFOX_SPEC.exe_name))
            if os.path.isfile(candidate):
                found.append(candidate)
    return found


# ============================================================ installation info
def _read_channel(install_dir: str) -> Optional[str]:
    prefs_text, _ = read_text_file(os.path.join(install_dir, "defaults", "pref", "channel-prefs.js"))
    if prefs_text:
        m = re.search(r'app\.update\.channel"\s*,\s*"([^"]+)"', prefs_text)
        if m:
            return m.group(1)
    ini, _ = read_ini(os.path.join(install_dir, "update-settings.ini"))
    if ini and ini.has_option("Settings", "ACCEPTED_MAR_CHANNEL_IDS"):
        return ini.get("Settings", "ACCEPTED_MAR_CHANNEL_IDS")
    return None


def _build_browser_info(exe_path: str, root_drive: str, logger: AnalysisLogger) -> BrowserInfo:
    info = BrowserInfo(name=FIREFOX_SPEC.name, executable_path=exe_path,
                       executable_exists=os.path.isfile(exe_path),
                       installation_path=os.path.dirname(exe_path))
    if not info.executable_exists:
        info.notes.append("Executable not found at the given path.")
        logger.warning(f"Firefox executable not found: {exe_path}")
        return info
    logger.info(f"Firefox executable found: {exe_path}")
    if os.path.basename(exe_path).lower() != FIREFOX_SPEC.exe_name:
        logger.warning(f"Executable is not named {FIREFOX_SPEC.exe_name}; analysing anyway.")
    info.executable_sha256 = sha256_file(exe_path)

    app_ini, error = read_ini(os.path.join(info.installation_path, "application.ini"))
    if app_ini and app_ini.has_section("App"):
        get = lambda key: app_ini.get("App", key) if app_ini.has_option("App", key) else None
        info.edition, info.vendor = get("Name"), get("Vendor")
        info.build_id = get("BuildID")
        if get("Version"):
            info.version, info.version_source = get("Version"), "application.ini"
    else:
        logger.warning(f"application.ini unavailable ({error}).")
    if not info.version:
        version = get_file_version(exe_path)
        if version:
            info.version, info.version_source = version, "executable version resource"
    info.update_channel = _read_channel(info.installation_path)
    if info.version:
        logger.info(f"Firefox version: {info.version} ({info.version_source}), "
                    f"channel: {info.update_channel or 'unknown'}")
    else:
        logger.warning("Firefox version could not be determined.")

    relative, candidates, exact_letter = compute_install_hash_candidates(
        info.installation_path, root_drive)
    info.install_path_for_hash = relative
    info.install_hash_candidates = candidates
    if candidates:
        if exact_letter:
            logger.info(f"Install hash (as {exact_letter}:\\{relative}): {candidates[exact_letter]}")
        info.notes.append("Firefox derives the install hash from the physical install path after "
                          "following symlinks/junctions; a symlinked install may not match.")
    else:
        logger.warning("Could not derive an install-relative path; install-hash matching skipped.")
    return info


# ============================================================ profiles.ini handling
_ABS_WIN = re.compile(r"^[A-Za-z]:[\\/]")


def _norm_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _resolve_profile_path(raw: str, is_relative: Optional[bool], firefox_root: str,
                          root_drive: str) -> str:
    """Resolve a Path= value. Absolute Windows paths are re-mapped onto root_drive so a
    mounted image never resolves to the LIVE system's files."""
    raw = raw.strip()
    norm = raw.replace("\\", "/")
    if is_relative is None:
        is_relative = not (_ABS_WIN.match(raw) or norm.startswith("//"))
    if is_relative:
        return os.path.normpath(os.path.join(firefox_root, *[p for p in norm.split("/") if p]))
    candidates = []
    m = re.match(r"^[A-Za-z]:/(.*)$", norm)
    if m:
        candidates.append(os.path.normpath(os.path.join(root_drive, *[p for p in m.group(1).split("/") if p])))
    tail = norm.rstrip("/").split("/")[-1]
    candidates.append(os.path.join(firefox_root, "Profiles", tail))
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def _is_valid_profile_dir(path: str) -> bool:
    return os.path.isdir(path) and any(os.path.isfile(os.path.join(path, m)) for m in PROFILE_MARKERS)


def _parse_profiles_ini(firefox_root: str, root_drive: str, logger: AnalysisLogger,
                        user: str) -> Tuple[List[Dict], Dict[str, Dict]]:
    """Return (profile_entries, install_sections{HASH: {default_path, locked, source}})."""
    entries: List[Dict] = []
    installs: Dict[str, Dict] = {}

    ini, error = read_ini(os.path.join(firefox_root, "profiles.ini"))
    if error:
        logger.warning(f"profiles.ini unavailable for user '{user}': {error}")
    else:
        for section in ini.sections():
            items = dict(ini.items(section))
            if re.fullmatch(r"Profile\d+", section, re.IGNORECASE) and items.get("Path"):
                is_rel = items.get("IsRelative")
                resolved = _resolve_profile_path(
                    items["Path"], None if is_rel is None else is_rel.strip() == "1",
                    firefox_root, root_drive)
                entries.append({"section": section, "name": items.get("Name"),
                                "path": resolved, "is_default": items.get("Default", "0").strip() == "1"})
            elif section.lower().startswith("install") and len(section) > 7:
                digest = section[7:].upper()
                if items.get("Default"):
                    installs[digest] = {
                        "path": _resolve_profile_path(items["Default"], None, firefox_root, root_drive),
                        "locked": items.get("Locked", "0").strip() == "1",
                        "source": f"profiles.ini [{section}]"}

    legacy, _ = read_ini(os.path.join(firefox_root, "installs.ini"))
    if legacy:
        for section in legacy.sections():
            if legacy.has_option(section, "Default"):
                digest = section.strip().upper()
                installs.setdefault(digest, {
                    "path": _resolve_profile_path(legacy.get(section, "Default"), None,
                                                  firefox_root, root_drive),
                    "locked": legacy.has_option(section, "Locked")
                              and legacy.get(section, "Locked").strip() == "1",
                    "source": f"installs.ini [{section}]"})
    return entries, installs


def _compat_points_to_install(profile_path: str, install_dir: str) -> Tuple[Optional[str], bool]:
    """Does compatibility.ini name this install directory? Drive letter and case ignored.
    Returns (LastPlatformDir value, matches)."""
    ini, _ = read_ini(os.path.join(profile_path, "compatibility.ini"))
    if not ini or not ini.has_section("Compatibility"):
        return None, False
    target = re.sub(r"^[A-Za-z]:", "", str(PureWindowsPath(install_dir))).lower().rstrip("\\")
    seen = None
    for key in ("LastPlatformDir", "LastAppDir"):
        if ini.has_option("Compatibility", key):
            value = ini.get("Compatibility", key).strip()
            seen = seen or value
            normalized = re.sub(r"^[A-Za-z]:", "", str(PureWindowsPath(value))).lower().rstrip("\\")
            if normalized == target or normalized.startswith(target + "\\"):
                return value, True
    return seen, False


def _portable_candidates(exe_path: str) -> List[str]:
    """Profile folders that sit next to the exe (portable builds), nearest first."""
    exe_dir = os.path.dirname(exe_path)
    parent = os.path.dirname(exe_dir)
    grandparent = os.path.dirname(parent)
    options = [os.path.join(exe_dir, "profile"), os.path.join(exe_dir, "Data", "profile"),
               os.path.join(parent, "Data", "profile"), os.path.join(grandparent, "Data", "profile"),
               os.path.join(parent, "Profile"), os.path.join(grandparent, "Profile")]
    seen, result = set(), []
    for option in options:
        key = _norm_key(option)
        if key not in seen and _is_valid_profile_dir(option):
            seen.add(key)
            result.append(option)
    return result


def _collect_profile_specs(root_drive: str, exe_path: str, info: BrowserInfo,
                           logger: AnalysisLogger) -> List[Dict]:
    """Classify every Firefox profile found on the drive relative to THIS installation."""
    specs: Dict[str, Dict] = {}   # normalized path -> spec; strongest attribution wins
    rank = {"confirmed": 0, "inferred": 1, "unattributed": 2}

    def add(spec: Dict) -> None:
        key = _norm_key(spec["path"])
        current = specs.get(key)
        if current is None or rank[spec["attribution"]] < rank[current["attribution"]]:
            specs[key] = spec

    for path in _portable_candidates(exe_path):
        logger.info(f"Portable/adjacent profile found: {path}")
        add({"directory_name": os.path.basename(path), "path": path,
             "windows_user": "portable/adjacent", "attribution": "confirmed",
             "attribution_basis": "profile folder located next to the executable (portable layout)",
             "profile_name": None})

    install_dir = info.installation_path or os.path.dirname(exe_path)
    candidates = info.install_hash_candidates
    exact_letter = None
    m = re.match(r"^([A-Za-z]):", root_drive or "")
    if m:
        exact_letter = m.group(1).upper()
    # hash -> (letter, kind); the drive's own letter is tried first
    hash_lookup: Dict[str, Tuple[str, str]] = {}
    for letter, digest in candidates.items():
        kind = "exact" if letter == exact_letter else "drive-letter substituted"
        if digest not in hash_lookup or kind == "exact":
            hash_lookup[digest] = (letter, kind)

    for user in _list_windows_users(root_drive, logger):
        firefox_root = os.path.normpath(os.path.join(root_drive, "Users", user,
                                                     FIREFOX_SPEC.per_user_data_dir))
        if not os.path.isdir(firefox_root):
            continue
        logger.info(f"Firefox data root found for user '{user}': {firefox_root}")
        if firefox_root not in info.user_data_paths:
            info.user_data_paths.append(firefox_root)

        entries, installs = _parse_profiles_ini(firefox_root, root_drive, logger, user)
        name_by_key = {_norm_key(e["path"]): e for e in entries}

        # 1) install-hash match (exact letter preferred over substituted)
        matches = [(digest, *hash_lookup[digest]) for digest in installs if digest in hash_lookup]
        if any(kind == "exact" for _, _, kind in matches):
            matches = [mt for mt in matches if mt[2] == "exact"]
        if len(matches) > 1:
            logger.warning(f"User '{user}': several install sections match this install path under "
                           f"different drive letters ({', '.join(d for d, _, _ in matches)}); "
                           "all are attributed.")
        matched_paths: Set[str] = set()
        for digest, letter, kind in matches:
            link = installs[digest]
            if not os.path.isdir(link["path"]):
                logger.warning(f"{link['source']} points to a missing profile folder: {link['path']}")
                continue
            if info.matched_install_hash is None:
                info.matched_install_hash, info.install_hash_match_kind = digest, kind
            if kind != "exact":
                logger.warning(f"Install hash {digest} matched only as {letter}:\\"
                               f"{info.install_path_for_hash} (original volume letter differs from "
                               f"{root_drive}).")
            entry = name_by_key.get(_norm_key(link["path"]))
            add({"directory_name": os.path.basename(link["path"]), "path": link["path"],
                 "windows_user": user, "attribution": "confirmed",
                 "attribution_basis": f"{link['source']} hash {digest} = install hash of "
                                      f"{letter}:\\{info.install_path_for_hash} ({kind})"
                                      + (", locked to this install" if link["locked"] else ""),
                 "profile_name": entry["name"] if entry else None})
            matched_paths.add(_norm_key(link["path"]))
        has_install_match = bool(matched_paths)

        # 2) everything else on this user: inferred or unattributed
        known: Dict[str, Dict] = {_norm_key(e["path"]): e for e in entries}
        profiles_dir = os.path.join(firefox_root, "Profiles")
        if os.path.isdir(profiles_dir):
            try:
                for name in sorted(os.listdir(profiles_dir)):
                    path = os.path.join(profiles_dir, name)
                    if _is_valid_profile_dir(path) and _norm_key(path) not in known:
                        known[_norm_key(path)] = {"section": None, "name": None, "path": path,
                                                  "is_default": False}
            except OSError as exc:
                logger.warning(f"Unable to list {profiles_dir}: {exc}")
        for key, entry in known.items():
            if key in matched_paths:
                continue
            path = entry["path"]
            if not _is_valid_profile_dir(path):
                logger.warning(f"Profile entry skipped (missing or not a profile): {path}")
                continue
            listed = "listed in profiles.ini" if entry["section"] else "not listed in profiles.ini"
            _, compat_match = _compat_points_to_install(path, install_dir)
            if compat_match:
                attribution, basis = "inferred", ("compatibility.ini names this installation's "
                                                  "directory as the last one that used the profile")
            elif entry["is_default"] and not has_install_match:
                others = [d for d in installs if d not in hash_lookup]
                attribution = "inferred"
                basis = ("legacy default profile (Default=1) and no [Install...] entry matches this "
                         "installation" + (f"; other installs recorded: {', '.join(others)}" if others else ""))
            else:
                attribution, basis = "unattributed", f"{listed}; no link to this installation found"
            add({"directory_name": os.path.basename(path), "path": path, "windows_user": user,
                 "attribution": attribution, "attribution_basis": basis,
                 "profile_name": entry["name"]})

    return sorted(specs.values(), key=lambda s: (rank[s["attribution"]], s["windows_user"], s["path"]))


# ============================================================ SQLite access
def _open_sqlite_copy(source: str, temp_dir: str, logger: AnalysisLogger
                      ) -> Tuple[sqlite3.Connection, str, Dict[str, Optional[str]]]:
    """Return (connection, access_method, hashes). Works on a copy incl. -wal / -journal."""
    base = os.path.basename(source)
    copy_path = os.path.join(temp_dir, base)
    hashes: Dict[str, Optional[str]] = {}
    try:
        shutil.copyfile(source, copy_path)
        hashes["db_sha256"] = sha256_file(copy_path)
        included = []
        for suffix in ("-wal", "-journal"):
            side = source + suffix
            if os.path.isfile(side):
                shutil.copyfile(side, copy_path + suffix)
                hashes[suffix[1:] + "_sha256"] = sha256_file(copy_path + suffix)
                included.append(suffix[1:])
        method = "temporary copy" + (f" + {', '.join(included)}" if included else "")
        return sqlite3.connect(copy_path), method, hashes
    except OSError as exc:
        logger.warning(f"Could not copy {base} ({exc}); is Firefox running? Trying read-only "
                       "direct access (recent entries in the -wal file will be missing).")
    try:
        uri = Path(source).resolve().as_uri() + "?mode=ro&immutable=1"
        return sqlite3.connect(uri, uri=True), "direct read-only (immutable, WAL ignored)", hashes
    except sqlite3.Error as exc:
        raise DatabaseAccessError(f"database locked or inaccessible ({exc})")


def _with_database(source: str, logger: AnalysisLogger, reader: Callable[[sqlite3.Connection], Any]
                   ) -> Tuple[Any, str, Dict[str, Optional[str]]]:
    temp_dir = tempfile.mkdtemp(prefix="bfa_ff_")
    try:
        connection, method, hashes = _open_sqlite_copy(source, temp_dir, logger)
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        try:
            return reader(connection), method, hashes
        except sqlite3.DatabaseError as exc:
            raise DatabaseAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)   # removes only OUR temp copy


# ============================================================ per-artifact readers
DOWNLOAD_STATES = {0: "in progress", 1: "finished", 2: "failed", 3: "canceled", 4: "paused"}


def _read_places(connection: sqlite3.Connection, profile: str, options: AnalysisOptions,
                 logger: AnalysisLogger) -> Dict[str, Any]:
    out: Dict[str, Any] = {"history": [], "first_visit": None, "visit_rows": 0, "unvisited": 0,
                           "bookmarks": [], "downloads": []}
    cursor = connection.execute(
        "SELECT url, title, visit_count, last_visit_date, typed, hidden FROM moz_places "
        "ORDER BY last_visit_date DESC")
    for url, title, visit_count, last_visit, typed, hidden in cursor:
        if not (visit_count or last_visit):
            out["unvisited"] += 1    # bookmark-only / never-visited entries
            continue
        out["history"].append(HistoryRecord(
            url=url or "", title=title or "", visit_time=firefox_time_to_string(last_visit),
            visit_count=int(visit_count or 0), typed=int(typed or 0), hidden=int(hidden or 0),
            profile=profile))
    try:
        row = connection.execute(
            "SELECT MIN(visit_date), COUNT(*) FROM moz_historyvisits WHERE visit_date > 0").fetchone()
        out["first_visit"] = firefox_time_to_string(row[0]) if row else None
        out["visit_rows"] = int(row[1]) if row and row[1] else 0
    except sqlite3.Error:
        logger.warning(f"'moz_historyvisits' unavailable for {profile}; first visit estimated.")

    if options.collect_bookmarks:
        try:
            rows = connection.execute(
                "SELECT b.id, b.parent, b.type, b.title, p.url, b.dateAdded, b.lastModified "
                "FROM moz_bookmarks b LEFT JOIN moz_places p ON p.id = b.fk").fetchall()
            folders = {r[0]: (r[1], r[3] or "") for r in rows}

            def folder_path(parent_id: Any) -> str:
                parts, guard = [], 0
                while parent_id in folders and guard < 64:
                    parent_id, title = folders[parent_id]
                    if title:
                        parts.append(title)
                    guard += 1
                return "/".join(reversed(parts))

            for _id, parent, kind, title, url, added, modified in rows:
                if kind == 1 and url:
                    out["bookmarks"].append(BookmarkRecord(
                        title=title or "", url=url, folder=folder_path(parent),
                        date_added=firefox_time_to_string(added),
                        last_modified=firefox_time_to_string(modified), profile=profile))
        except sqlite3.Error as exc:
            logger.warning(f"Bookmarks unavailable for {profile}: {exc}")

    if options.collect_downloads:
        try:
            grouped: Dict[str, Dict[str, Any]] = {}
            query = ("SELECT p.url, n.name, a.content FROM moz_annos a "
                     "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
                     "JOIN moz_places p ON p.id = a.place_id "
                     "WHERE n.name IN ('downloads/destinationFileURI', 'downloads/metaData')")
            for url, name, content in connection.execute(query):
                grouped.setdefault(url, {})[name] = content
            for url, annos in grouped.items():
                meta: Dict[str, Any] = {}
                try:
                    meta = json.loads(annos.get("downloads/metaData") or "{}")
                except (ValueError, TypeError):
                    pass
                state = meta.get("state")
                out["downloads"].append(DownloadRecord(
                    source_url=url, target_path=annos.get("downloads/destinationFileURI"),
                    state=(DOWNLOAD_STATES.get(state, f"code {state}") if state is not None else None),
                    end_time=millis_to_string(meta.get("endTime")),
                    file_size=meta.get("fileSize") if isinstance(meta.get("fileSize"), int) else None,
                    profile=profile))
        except sqlite3.Error as exc:
            logger.warning(f"Download records unavailable for {profile}: {exc}")
    return out


def _read_form_history(connection: sqlite3.Connection, profile: str) -> List[FormHistoryRecord]:
    rows = connection.execute("SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
                              "FROM moz_formhistory ORDER BY lastUsed DESC")
    return [FormHistoryRecord(field_name=f or "", value=v or "", times_used=int(t or 0),
                              first_used=firefox_time_to_string(fu),
                              last_used=firefox_time_to_string(lu), profile=profile)
            for f, v, t, fu, lu in rows]


def _cookie_expiry(value: Any) -> Optional[str]:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return millis_to_string(number) if number > 10 ** 11 else _unix_to_string(number, "s")


def _read_cookies(connection: sqlite3.Connection, profile: str) -> List[CookieRecord]:
    rows = connection.execute("SELECT host, name, path, creationTime, lastAccessed, expiry, "
                              "isSecure, isHttpOnly FROM moz_cookies ORDER BY lastAccessed DESC")
    return [CookieRecord(host=h or "", name=n or "", path=p or "",
                         created=firefox_time_to_string(c), last_accessed=firefox_time_to_string(a),
                         expiry=_cookie_expiry(e), secure=bool(s), http_only=bool(ho), profile=profile)
            for h, n, p, c, a, e, s, ho in rows]


# ============================================================ profile metadata
PREF_PATTERN = re.compile(r'^user_pref\("([^"]+)",\s*(.*?)\);\s*$')
INTERESTING_PREFS = (
    "intl.accept_languages", "browser.startup.homepage", "browser.download.dir",
    "browser.download.lastDir", "browser.download.folderList", "extensions.lastAppVersion",
    "places.history.enabled", "browser.privatebrowsing.autostart",
    "privacy.sanitize.sanitizeOnShutdown", "privacy.clearOnShutdown.history",
    "privacy.clearOnShutdown.cookies", "privacy.clearOnShutdown_v2.historyFormDataAndDownloads",
    "privacy.history.custom", "network.cookie.lifetimePolicy", "browser.formfill.enable",
    "browser.cache.disk.enable", "services.sync.username",
)


def _parse_prefs_js(path: str) -> Tuple[Dict[str, Any], Optional[str]]:
    text, error = read_text_file(path)
    if error:
        return {}, error
    prefs: Dict[str, Any] = {}
    wanted = set(INTERESTING_PREFS)
    for line in text.splitlines():
        m = PREF_PATTERN.match(line.strip())
        if not m or m.group(1) not in wanted:
            continue
        raw = m.group(2).strip()
        if raw in ("true", "false"):
            value: Any = raw == "true"
        elif re.fullmatch(r"-?\d+", raw):
            value = int(raw)
        else:
            value = raw[1:-1].replace('\\"', '"').replace("\\\\", "\\") if raw.startswith('"') else raw
        prefs[m.group(1)] = value
    return prefs, None


def _read_profile_metadata(spec: Dict, profile: ProfileResult, info: BrowserInfo,
                           logger: AnalysisLogger) -> None:
    metadata = profile.metadata
    metadata["windows_user"] = spec["windows_user"]
    profile.display_name = spec.get("profile_name") or None
    metadata["profiles_ini_name"] = spec.get("profile_name")

    times, error = read_json_file(os.path.join(spec["path"], "times.json"))
    if isinstance(times, dict):
        created = millis_to_string(times.get("created"))
        first_use = millis_to_string(times.get("firstUse"))
        if created:
            metadata["profile_creation_time"] = created
        if first_use:
            metadata["profile_first_use"] = first_use
    elif error and error != "file not found":
        logger.warning(f"times.json unavailable for {profile.directory_name}: {error}")

    compat, compat_error = read_ini(os.path.join(spec["path"], "compatibility.ini"))
    if compat and compat.has_section("Compatibility"):
        for key, label in (("LastVersion", "compat_last_version"),
                           ("LastPlatformDir", "compat_last_platform_dir"),
                           ("LastAppDir", "compat_last_app_dir")):
            if compat.has_option("Compatibility", key):
                metadata[label] = compat.get("Compatibility", key)
        _, points_here = _compat_points_to_install(spec["path"], info.installation_path or "")
        metadata["compat_names_this_installation"] = points_here
    elif compat_error and compat_error != "file not found":
        logger.warning(f"compatibility.ini unavailable for {profile.directory_name}: {compat_error}")

    prefs, prefs_error = _parse_prefs_js(os.path.join(spec["path"], "prefs.js"))
    if prefs_error:
        metadata["prefs_status"] = f"unavailable ({prefs_error})"
        logger.warning(f"prefs.js unavailable for {profile.directory_name}: {prefs_error}")
    else:
        metadata["prefs_status"] = "read"
        # Only record whether a Sync account is linked, not the account name.
        metadata["sync_account_configured"] = bool(prefs.pop("services.sync.username", None))
        if prefs:
            metadata["selected_prefs"] = prefs
        if prefs.get("extensions.lastAppVersion"):
            metadata["last_app_version"] = prefs["extensions.lastAppVersion"]
        if prefs.get("places.history.enabled") is False:
            logger.warning(f"{profile.directory_name}: history recording is disabled in prefs.js.")
        cleared = [k for k in ("privacy.sanitize.sanitizeOnShutdown", "privacy.clearOnShutdown.history",
                               "browser.privatebrowsing.autostart") if prefs.get(k) is True]
        if cleared:
            logger.warning(f"{profile.directory_name}: history may be cleared automatically "
                           f"({', '.join(cleared)}); empty history is NOT proof of non-use.")

    for label, filename in (("prefs_file", "prefs.js"), ("places_file", "places.sqlite"),
                            ("cookies_file", "cookies.sqlite"), ("formhistory_file", "formhistory.sqlite")):
        details = file_metadata(os.path.join(spec["path"], filename))
        if details:
            metadata[label] = details


def _read_extensions(path: str, profile_name: str, logger: AnalysisLogger) -> List[ExtensionRecord]:
    data, error = read_json_file(path)
    if error:
        if error != "file not found":
            logger.warning(f"extensions.json unavailable for {profile_name}: {error}")
        return []
    addons = data.get("addons") if isinstance(data, dict) else None
    result: List[ExtensionRecord] = []
    for addon in addons or []:
        if not isinstance(addon, dict):
            continue
        result.append(ExtensionRecord(
            addon_id=str(addon.get("id", "")), name=dig(addon, "defaultLocale", "name"),
            version=addon.get("version"), addon_type=addon.get("type"), location=addon.get("location"),
            active=addon.get("active"), installed=millis_to_string(addon.get("installDate")),
            updated=millis_to_string(addon.get("updateDate")), profile=profile_name))
    return result


# ============================================================ statistics
def compute_statistics(records: List[HistoryRecord], first_visit: Optional[str] = None,
                       visit_rows: int = 0, unvisited: int = 0) -> HistoryStatistics:
    times = [r.visit_time for r in records if r.visit_time]
    domains = {get_domain(r.url) for r in records} - {None}
    return HistoryStatistics(
        history_record_count=len(records), total_visits=sum(r.visit_count for r in records),
        visit_row_count=visit_rows, unvisited_place_count=unvisited,
        unique_url_count=len({r.url for r in records}), unique_domain_count=len(domains),
        typed_url_count=sum(1 for r in records if r.typed),
        first_visit=first_visit or (min(times) if times else None),
        last_visit=max(times) if times else None)


# ============================================================ orchestration
def _record_artifact(profile: ProfileResult, name: str, path: str, status: str,
                     method: Optional[str] = None, hashes: Optional[Dict] = None) -> None:
    profile.artifacts[name] = {"path": path, "status": status, "access_method": method,
                               **(hashes or {}), **(file_metadata(path) or {})}


def _analyze_profile(spec: Dict, info: BrowserInfo, options: AnalysisOptions,
                     logger: AnalysisLogger) -> ProfileResult:
    name = spec["directory_name"]
    profile = ProfileResult(directory_name=name, path=spec["path"], windows_user=spec["windows_user"],
                            attribution=spec["attribution"], attribution_basis=spec["attribution_basis"])
    logger.info(f"Analyzing profile '{name}' [{spec['attribution']}] "
                f"(Windows user: {spec['windows_user']})...")
    _read_profile_metadata(spec, profile, info, logger)

    # ---- places.sqlite: history, bookmarks, downloads
    places_path = os.path.join(spec["path"], "places.sqlite")
    if not os.path.isfile(places_path):
        profile.history_status = "Not found"
        logger.warning(f"places.sqlite not found for {name} (unavailable, not proof of no browsing).")
    else:
        profile.history_db_path = places_path
        logger.info("places.sqlite found. Reading history...")
        try:
            data, method, hashes = _with_database(
                places_path, logger, lambda c: _read_places(c, name, options, logger))
            profile.history = data["history"]
            profile.bookmarks = data["bookmarks"]
            profile.downloads = data["downloads"]
            profile.history_db_sha256 = hashes.get("db_sha256")
            profile.statistics = compute_statistics(data["history"], data["first_visit"],
                                                    data["visit_rows"], data["unvisited"])
            profile.history_status = (f"Read OK ({method})" if data["history"]
                                      else f"Read OK, no records ({method})")
            _record_artifact(profile, "places.sqlite", places_path, "read", method, hashes)
            logger.info(f"{name}: {len(profile.history):,} history records, "
                        f"{profile.statistics.unique_domain_count:,} unique domains, "
                        f"{len(profile.bookmarks):,} bookmarks, {len(profile.downloads):,} downloads.")
        except DatabaseAccessError as exc:
            profile.history_status = f"Unavailable: {exc}"
            _record_artifact(profile, "places.sqlite", places_path, f"unavailable: {exc}")
            logger.warning(f"places.sqlite unavailable for {name}: {exc}")

    # ---- optional databases
    def optional_db(filename: str, enabled: bool, reader: Callable, target: str) -> None:
        if not enabled:
            return
        path = os.path.join(spec["path"], filename)
        if not os.path.isfile(path):
            return
        try:
            rows, method, hashes = _with_database(path, logger, reader)
            setattr(profile, target, rows)
            _record_artifact(profile, filename, path, "read", method, hashes)
            logger.info(f"{name}: {len(rows):,} record(s) from {filename}.")
        except DatabaseAccessError as exc:
            _record_artifact(profile, filename, path, f"unavailable: {exc}")
            logger.warning(f"{filename} unavailable for {name}: {exc}")

    optional_db("formhistory.sqlite", options.collect_form_history,
                lambda c: _read_form_history(c, name), "form_history")
    optional_db("cookies.sqlite", options.collect_cookies,
                lambda c: _read_cookies(c, name), "cookies")
    if options.collect_extensions:
        profile.extensions = _read_extensions(os.path.join(spec["path"], "extensions.json"), name, logger)
    return profile


def _unanalyzed_profile(spec: Dict, info: BrowserInfo, logger: AnalysisLogger) -> ProfileResult:
    profile = ProfileResult(directory_name=spec["directory_name"], path=spec["path"],
                            windows_user=spec["windows_user"], attribution="unattributed",
                            attribution_basis=spec["attribution_basis"],
                            history_status="Not analyzed (not tied to this installation)")
    _read_profile_metadata(spec, profile, info, AnalysisLogger())   # metadata only, quiet
    return profile


def _build_summary(info: BrowserInfo, profiles: List[ProfileResult],
                   unattributed: List[ProfileResult]) -> Dict:
    all_records = [r for p in profiles for r in p.history]
    stats = compute_statistics(all_records)
    firsts = [p.statistics.first_visit for p in profiles if p.statistics.first_visit]
    return {
        "installation": {"executable_path": info.executable_path, "version": info.version,
                         "edition": info.edition, "update_channel": info.update_channel,
                         "install_hash": info.matched_install_hash,
                         "install_hash_match": info.install_hash_match_kind},
        "profile_count": len(profiles),
        "confirmed_profile_count": sum(1 for p in profiles if p.attribution == "confirmed"),
        "inferred_profile_count": sum(1 for p in profiles if p.attribution == "inferred"),
        "unattributed_profile_count": len(unattributed),
        "profiles_with_history": sum(1 for p in profiles if p.history_status.startswith("Read OK")),
        "windows_users": sorted({p.windows_user for p in profiles}),
        "history_record_count": stats.history_record_count,
        "total_visits": stats.total_visits,
        "unique_url_count": stats.unique_url_count,
        "unique_domain_count": stats.unique_domain_count,
        "bookmark_count": sum(len(p.bookmarks) for p in profiles),
        "download_count": sum(len(p.downloads) for p in profiles),
        "form_history_count": sum(len(p.form_history) for p in profiles),
        "cookie_count": sum(len(p.cookies) for p in profiles),
        "extension_count": sum(len(p.extensions) for p in profiles),
        "first_visit": min(firsts) if firsts else None,
        "last_visit": stats.last_visit,
    }


def _run_analysis(root_drive: str, exe_path: str, options: AnalysisOptions,
                  logger: AnalysisLogger, result: AnalysisResult) -> None:
    if not root_drive or not os.path.isdir(root_drive):
        logger.error(f"Selected drive is not accessible: {root_drive!r}")
        return
    if not exe_path or not os.path.isfile(exe_path):
        logger.error(f"Firefox executable was not found at the specified location: {exe_path!r}")
        return
    exe_path = os.path.normpath(exe_path)
    try:
        if os.path.relpath(exe_path, root_drive).startswith(".."):
            logger.warning("The executable is not located under the selected drive; user data is "
                           "still searched on the selected drive only.")
    except ValueError:
        logger.warning("The executable is on a different volume than the selected drive.")

    logger.info("Starting Firefox analysis (single installation)...")
    info = _build_browser_info(exe_path, root_drive, logger)
    result.browser = info

    specs = _collect_profile_specs(root_drive, exe_path, info, logger)
    if not info.user_data_paths and not any(s["windows_user"] == "portable/adjacent" for s in specs):
        logger.warning("No Firefox data directory found on this drive; no profiles to analyze.")
    mine = [s for s in specs if s["attribution"] == "confirmed"
            or (s["attribution"] == "inferred" and options.include_inferred)]
    other = [s for s in specs if s not in mine]
    logger.info(f"Profiles tied to this installation: {len(mine)} "
                f"({sum(1 for s in mine if s['attribution'] == 'confirmed')} confirmed); "
                f"other/unattributed profiles on drive: {len(other)}.")
    if info.install_hash_candidates and info.matched_install_hash is None and \
            not any(s["attribution"] == "confirmed" for s in mine):
        logger.warning("No [Install<HASH>] entry matches this installation; this installation may "
                       "never have been run by a user on this drive, or was started with -profile.")

    for spec in mine:
        try:
            result.profiles.append(_analyze_profile(spec, info, options, logger))
        except Exception as exc:
            logger.error(f"Profile '{spec['directory_name']}' failed: {exc!r}")
            result.profiles.append(ProfileResult(
                directory_name=spec["directory_name"], path=spec["path"],
                windows_user=spec["windows_user"], attribution=spec["attribution"],
                attribution_basis=spec["attribution_basis"],
                history_status=f"Analysis failed: {exc!r}"))

    for spec in other:
        try:
            if options.include_unattributed:
                result.unattributed_profiles.append(_analyze_profile(spec, info, options, logger))
            else:
                result.unattributed_profiles.append(_unanalyzed_profile(spec, info, logger))
        except Exception as exc:
            logger.error(f"Profile '{spec['directory_name']}' failed: {exc!r}")

    result.summary = _build_summary(info, result.profiles, result.unattributed_profiles)
    logger.info("Analysis completed.")


# ================================================================ public entry points
def analyze_firefox(selected_drive: str, selected_browser: str = "Mozilla Firefox",
                    target_exe_path: Optional[str] = None,
                    log_callback: Optional[Callable[[str], None]] = None,
                    options: Optional[AnalysisOptions] = None) -> AnalysisResult:
    """Analyse ONE Firefox installation (target_exe_path) and only its profiles/activity.

    If target_exe_path is None, standard locations are searched; the analysis proceeds
    only when exactly ONE installation is found (installations are never merged)."""
    logger = AnalysisLogger(callback=log_callback)
    options = options or AnalysisOptions()
    result = AnalysisResult(drive=selected_drive, started_utc=now_utc_string())
    try:
        if not selected_drive or not selected_browser:
            logger.error("A drive and a browser must both be selected.")
        elif selected_browser.strip().lower() not in SUPPORTED_BROWSER_NAMES:
            logger.error(f"'{selected_browser}' is not supported (only Mozilla Firefox).")
        else:
            exe = target_exe_path
            if not exe:
                found = discover_firefox_installations(selected_drive, logger) \
                    if os.path.isdir(selected_drive or "") else []
                if len(found) == 1:
                    exe = found[0]
                    logger.info(f"No executable given; using the only installation found: {exe}")
                elif not found:
                    logger.error("No Firefox installation found; pass target_exe_path explicitly.")
                else:
                    logger.error("Several Firefox installations found; pass target_exe_path for the "
                                 "one to analyse (or use analyze_all_firefox_installations): "
                                 + "; ".join(found))
            if exe:
                _run_analysis(selected_drive, exe, options, logger, result)
    except Exception as exc:
        logger.error(f"Unexpected failure: {exc!r}")
    result.warnings = list(logger.warnings)
    result.errors = list(logger.errors)
    result.log = list(logger.entries)
    result.finished_utc = now_utc_string()
    return result


def analyze_all_firefox_installations(selected_drive: str,
                                      log_callback: Optional[Callable[[str], None]] = None,
                                      options: Optional[AnalysisOptions] = None
                                      ) -> List[AnalysisResult]:
    """Convenience: one INDEPENDENT AnalysisResult per installation found on the drive."""
    exes = discover_firefox_installations(selected_drive) if os.path.isdir(selected_drive or "") else []
    return [analyze_firefox(selected_drive, "Mozilla Firefox", exe, log_callback, options)
            for exe in exes]


if __name__ == "__main__":
    # python firefox_analyzer.py D:\\ "D:\\Program Files\\Mozilla Firefox\\firefox.exe"
    drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    exe_arg = sys.argv[2] if len(sys.argv) > 2 else None
    outcome = analyze_firefox(drive, "Mozilla Firefox", exe_arg, log_callback=print)
    print(json.dumps(outcome.summary, indent=2))