"""
firefox_analyzer.py  --  standalone Mozilla Firefox analysis engine (per installation).

    from firefox_analyzer import analyze_firefox

    result = analyze_firefox(selected_drive, selected_browser, target_exe_path,
                             log_callback=None)

    selected_drive   : e.g. "D:\\"
    selected_browser : "Mozilla Firefox" (also "Firefox", "Firefox ESR",
                       "Firefox Developer Edition", "Firefox Nightly")
    target_exe_path  : full path of the EXACT firefox.exe to analyse
    log_callback     : optional function(str) receiving each log line live

It never raises; failures are in result.errors / result.warnings.

WHAT IT REPORTS (only for the installation given in target_exe_path)
    result.summary["profile_count"], ["profile_names"]
    result.summary["unique_url_count"], ["unique_domain_count"], ["bookmark_count"],
                   ["download_count"], ["extension_count"]
    result.websites_visited()   -> every website visit with its time (newest first)
    result.profiles[i]          -> per-profile name, path and the same counts / visits

HOW A PROFILE IS TIED TO THE INSTALLATION
    confirmed : profiles.ini / installs.ini [Install<HASH>] entry whose HASH is the
                install hash of THIS installation, or a portable profile folder
                next to the exe.
    inferred  : the profile's compatibility.ini names this installation's directory,
                or it is the legacy default profile and no [Install...] entry matches.
    Other profiles on the drive are NOT analysed; they are only listed by name in
    result.unattributed_profiles.
    (For a mounted image the original drive letter is unknown, so the install hash
    is tried under every letter A-Z.)

Forensic handling: paths derive from selected_drive only; SQLite files are COPIED
(with their -wal file, where Firefox keeps recent activity) to a temp folder and the
copy is queried; nothing is written to the source drive; Firefox is never launched.
"""

import configparser
import hashlib
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
    name: str
    exe_name: str
    system_install_dirs: tuple      # relative to drive root
    per_user_install_dirs: tuple    # relative to Users\<user>
    per_user_data_dir: str          # relative to Users\<user> (profiles.ini lives here)


@dataclass
class BrowserInfo:
    name: str
    version: Optional[str] = None
    executable_path: Optional[str] = None
    installation_path: Optional[str] = None
    executable_exists: bool = False
    install_path_for_hash: Optional[str] = None
    install_hash_candidates: Dict[str, str] = field(default_factory=dict)  # letter -> HASH
    matched_install_hash: Optional[str] = None
    install_hash_match_kind: Optional[str] = None   # "exact" | "drive-letter substituted"
    user_data_paths: List[str] = field(default_factory=list)


@dataclass
class VisitRecord:
    url: str
    title: str
    visit_time: Optional[str]       # UTC
    profile: str


@dataclass
class ProfileResult:
    directory_name: str
    path: str
    windows_user: str
    profile_name: str = ""                      # the name shown in Firefox (about:profiles)
    attribution: str = "unattributed"           # confirmed | inferred | unattributed
    attribution_basis: str = ""
    history_status: str = "Not analyzed"
    history_db_sha256: Optional[str] = None     # hash of the analysed copy of places.sqlite
    visits: List[VisitRecord] = field(default_factory=list)
    visit_count: int = 0
    unique_url_count: int = 0
    unique_domain_count: int = 0
    bookmark_count: int = 0
    download_count: int = 0
    extension_count: int = 0


@dataclass
class AnalysisResult:
    drive: str
    browser: Optional[BrowserInfo] = None
    profiles: List[ProfileResult] = field(default_factory=list)               # THIS installation
    unattributed_profiles: List[ProfileResult] = field(default_factory=list)  # name/path only
    summary: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    started_utc: Optional[str] = None
    finished_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def websites_visited(self) -> List[Dict[str, Any]]:
        """Every website visit across the installation's profiles, newest first.
        Each item: {"profile", "url", "title", "visit_time"} (visit_time is UTC)."""
        rows = [{"profile": v.profile, "url": v.url, "title": v.title, "visit_time": v.visit_time}
                for p in self.profiles for v in p.visits]
        rows.sort(key=lambda r: r["visit_time"] or "", reverse=True)
        return rows


# ================================================================== utilities
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def format_utc(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None


def firefox_time_to_string(value: Any) -> Optional[str]:
    """Firefox places timestamps: microseconds since 1970-01-01 UTC."""
    try:
        number = int(value)
        if number <= 0:
            return None
        return format_utc(UNIX_EPOCH + timedelta(microseconds=number))
    except (TypeError, ValueError, OverflowError):
        return None


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


def sha256_file(path: str) -> Optional[str]:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def get_domain(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None
    return host.lower() if host else None


# ============================================================ install hash
# Firefox names the [Install<HASH>] section in profiles.ini after
# CityHash64(<install directory as UTF-16LE>), printed as upper-case hex.
# (Verified: "C:\Program Files\Mozilla Firefox" -> 308046B0AF4A39CB.)
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
    return "%016X" % city_hash64(windows_install_dir.encode("utf-16-le"))


def compute_install_hash_candidates(install_dir: str, root_drive: str
                                    ) -> Tuple[Optional[str], Dict[str, str], Optional[str]]:
    """Return (drive_relative_path, {letter: HASH}, exact_letter)."""
    drive_letter = None
    match = re.match(r"^([A-Za-z]):", root_drive or "")
    if match:
        drive_letter = match.group(1).upper()
    try:
        relative = os.path.relpath(install_dir, root_drive)
    except ValueError:
        relative = None
    if relative is None or relative.startswith(".."):
        given = str(PureWindowsPath(install_dir))
        m = re.match(r"^([A-Za-z]):\\(.*)$", given)
        if not m:
            return None, {}, drive_letter
        relative = m.group(2)
        drive_letter = m.group(1).upper()
    relative = str(PureWindowsPath(relative)).rstrip("\\")
    return relative, {letter: firefox_install_hash(f"{letter}:\\{relative}")
                      for letter in string.ascii_uppercase}, drive_letter


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
    """firefox.exe paths found in standard locations. Each is an independent installation."""
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


def _build_browser_info(exe_path: str, root_drive: str, logger: AnalysisLogger) -> BrowserInfo:
    info = BrowserInfo(name=FIREFOX_SPEC.name, executable_path=exe_path,
                       executable_exists=os.path.isfile(exe_path),
                       installation_path=os.path.dirname(exe_path))
    logger.info(f"Firefox executable found: {exe_path}")
    if os.path.basename(exe_path).lower() != FIREFOX_SPEC.exe_name:
        logger.warning(f"Executable is not named {FIREFOX_SPEC.exe_name}; analysing anyway.")
    app_ini, _ = read_ini(os.path.join(info.installation_path, "application.ini"))
    if app_ini and app_ini.has_option("App", "Version"):
        info.version = app_ini.get("App", "Version")
        logger.info(f"Firefox version: {info.version}")
    relative, candidates, _ = compute_install_hash_candidates(info.installation_path, root_drive)
    info.install_path_for_hash = relative
    info.install_hash_candidates = candidates
    if not candidates:
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
    candidates.append(os.path.join(firefox_root, "Profiles", norm.rstrip("/").split("/")[-1]))
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return candidates[0]


def _is_valid_profile_dir(path: str) -> bool:
    return os.path.isdir(path) and any(os.path.isfile(os.path.join(path, m)) for m in PROFILE_MARKERS)


def _fallback_profile_name(directory_name: str) -> str:
    """'x1y2z3ab.default-release' -> 'default-release' (Firefox's random 8-char prefix)."""
    m = re.fullmatch(r"[a-z0-9]{8}\.(.+)", directory_name)
    return m.group(1) if m else directory_name


def _parse_profiles_ini(firefox_root: str, root_drive: str, logger: AnalysisLogger,
                        user: str) -> Tuple[List[Dict], Dict[str, Dict]]:
    """Return (profile_entries, install_sections{HASH: {path, locked, source}})."""
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
                entries.append({
                    "section": section, "name": items.get("Name"),
                    "path": _resolve_profile_path(items["Path"], None if is_rel is None
                                                  else is_rel.strip() == "1", firefox_root, root_drive),
                    "is_default": items.get("Default", "0").strip() == "1"})
            elif section.lower().startswith("install") and len(section) > 7 and items.get("Default"):
                installs[section[7:].upper()] = {
                    "path": _resolve_profile_path(items["Default"], None, firefox_root, root_drive),
                    "locked": items.get("Locked", "0").strip() == "1",
                    "source": f"profiles.ini [{section}]"}

    legacy, _ = read_ini(os.path.join(firefox_root, "installs.ini"))
    if legacy:
        for section in legacy.sections():
            if legacy.has_option(section, "Default"):
                installs.setdefault(section.strip().upper(), {
                    "path": _resolve_profile_path(legacy.get(section, "Default"), None,
                                                  firefox_root, root_drive),
                    "locked": legacy.has_option(section, "Locked")
                              and legacy.get(section, "Locked").strip() == "1",
                    "source": f"installs.ini [{section}]"})
    return entries, installs


def _compat_points_to_install(profile_path: str, install_dir: str) -> bool:
    """Does compatibility.ini name this install directory? Drive letter and case ignored."""
    ini, _ = read_ini(os.path.join(profile_path, "compatibility.ini"))
    if not ini or not ini.has_section("Compatibility"):
        return False
    target = re.sub(r"^[A-Za-z]:", "", str(PureWindowsPath(install_dir))).lower().rstrip("\\")
    for key in ("LastPlatformDir", "LastAppDir"):
        if ini.has_option("Compatibility", key):
            value = re.sub(r"^[A-Za-z]:", "", str(PureWindowsPath(ini.get("Compatibility", key).strip())))
            value = value.lower().rstrip("\\")
            if value == target or value.startswith(target + "\\"):
                return True
    return False


def _portable_candidates(exe_path: str) -> List[str]:
    """Profile folders next to the exe (portable builds), nearest first."""
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
    """Classify every Firefox profile on the drive relative to THIS installation."""
    specs: Dict[str, Dict] = {}   # normalized path -> spec; strongest attribution wins
    rank = {"confirmed": 0, "inferred": 1, "unattributed": 2}

    def add(spec: Dict) -> None:
        key = _norm_key(spec["path"])
        current = specs.get(key)
        if current is None or rank[spec["attribution"]] < rank[current["attribution"]]:
            specs[key] = spec

    for path in _portable_candidates(exe_path):
        logger.info(f"Portable/adjacent profile found: {path}")
        add({"directory_name": os.path.basename(path), "path": path, "windows_user": "portable/adjacent",
             "attribution": "confirmed", "profile_name": _fallback_profile_name(os.path.basename(path)),
             "attribution_basis": "profile folder located next to the executable (portable layout)"})

    install_dir = info.installation_path or os.path.dirname(exe_path)
    m = re.match(r"^([A-Za-z]):", root_drive or "")
    exact_letter = m.group(1).upper() if m else None
    hash_lookup: Dict[str, Tuple[str, str]] = {}   # HASH -> (letter, kind)
    for letter, digest in info.install_hash_candidates.items():
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
        by_key = {_norm_key(e["path"]): e for e in entries}

        # 1) install-hash match (exact drive letter preferred over substituted)
        matches = [(d, *hash_lookup[d]) for d in installs if d in hash_lookup]
        if any(kind == "exact" for _, _, kind in matches):
            matches = [mt for mt in matches if mt[2] == "exact"]
        matched_paths: Set[str] = set()
        for digest, letter, kind in matches:
            link = installs[digest]
            if not os.path.isdir(link["path"]):
                logger.warning(f"{link['source']} points to a missing profile folder: {link['path']}")
                continue
            if info.matched_install_hash is None:
                info.matched_install_hash, info.install_hash_match_kind = digest, kind
            entry = by_key.get(_norm_key(link["path"]))
            dirname = os.path.basename(link["path"])
            add({"directory_name": dirname, "path": link["path"], "windows_user": user,
                 "attribution": "confirmed",
                 "profile_name": (entry or {}).get("name") or _fallback_profile_name(dirname),
                 "attribution_basis": f"{link['source']} hash {digest} = install hash of "
                                      f"{letter}:\\{info.install_path_for_hash} ({kind})"})
            matched_paths.add(_norm_key(link["path"]))
        has_install_match = bool(matched_paths)

        # 2) every other profile of this user: inferred or unattributed
        known = dict(by_key)
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
            if key in matched_paths or not _is_valid_profile_dir(entry["path"]):
                continue
            path, dirname = entry["path"], os.path.basename(entry["path"])
            if _compat_points_to_install(path, install_dir):
                attribution = "inferred"
                basis = "compatibility.ini names this installation as the last one that used the profile"
            elif entry["is_default"] and not has_install_match:
                attribution = "inferred"
                basis = "legacy default profile and no [Install...] entry matches this installation"
            else:
                attribution, basis = "unattributed", "no link to this installation found"
            add({"directory_name": dirname, "path": path, "windows_user": user,
                 "attribution": attribution, "attribution_basis": basis,
                 "profile_name": entry.get("name") or _fallback_profile_name(dirname)})

    return sorted(specs.values(), key=lambda s: (rank[s["attribution"]], s["windows_user"], s["path"]))


# ============================================================ SQLite access
def _with_database(source: str, logger: AnalysisLogger,
                   reader: Callable[[sqlite3.Connection], Any]) -> Tuple[Any, str, Optional[str]]:
    """Run reader on a COPY of the database (plus its -wal / -journal). Returns
    (reader result, access method, sha256 of the copy)."""
    temp_dir = tempfile.mkdtemp(prefix="bfa_ff_")
    try:
        copy_path = os.path.join(temp_dir, os.path.basename(source))
        connection: Optional[sqlite3.Connection] = None
        digest: Optional[str] = None
        try:
            shutil.copyfile(source, copy_path)
            digest = sha256_file(copy_path)
            included = []
            for suffix in ("-wal", "-journal"):
                if os.path.isfile(source + suffix):
                    shutil.copyfile(source + suffix, copy_path + suffix)
                    included.append(suffix[1:])
            method = "temporary copy" + (f" + {', '.join(included)}" if included else "")
            connection = sqlite3.connect(copy_path)
        except OSError as exc:
            logger.warning(f"Could not copy {os.path.basename(source)} ({exc}); is Firefox running? "
                           "Trying read-only direct access (recent entries in the -wal file will be missing).")
        if connection is None:
            try:
                uri = Path(source).resolve().as_uri() + "?mode=ro&immutable=1"
                connection, method = sqlite3.connect(uri, uri=True), "direct read-only (immutable, WAL ignored)"
            except sqlite3.Error as exc:
                raise DatabaseAccessError(f"database locked or inaccessible ({exc})")
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        try:
            return reader(connection), method, digest
        except sqlite3.DatabaseError as exc:
            raise DatabaseAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)   # removes only OUR temp copy


def _read_places(connection: sqlite3.Connection, profile: str, logger: AnalysisLogger) -> Dict[str, Any]:
    """Visits (one row per visit, with time) plus bookmark and download counts.

    Pages Firefox marks 'hidden' (redirect hops, embedded frames) are excluded, the same
    as Firefox's own History window."""
    visits: List[VisitRecord] = []
    visits_table_ok = True
    try:
        for url, title, when in connection.execute(
                "SELECT p.url, p.title, v.visit_date FROM moz_historyvisits v "
                "JOIN moz_places p ON p.id = v.place_id WHERE p.hidden = 0"):
            visits.append(VisitRecord(url or "", title or "", firefox_time_to_string(when), profile))
    except sqlite3.Error:
        visits_table_ok = False
        logger.warning(f"'moz_historyvisits' unavailable for {profile}; using last-visit times only.")
    # pages that have a visit counter / last-visit time but no individual visit rows
    query = ("SELECT url, title, last_visit_date FROM moz_places WHERE hidden = 0 "
             "AND (visit_count > 0 OR last_visit_date IS NOT NULL)")
    if visits_table_ok:
        query += " AND id NOT IN (SELECT place_id FROM moz_historyvisits)"
    for url, title, when in connection.execute(query):
        visits.append(VisitRecord(url or "", title or "", firefox_time_to_string(when), profile))
    visits.sort(key=lambda v: v.visit_time or "", reverse=True)

    bookmarks = downloads = 0
    try:   # 'place:' entries are Firefox's built-in smart folders, not real bookmarks
        bookmarks = connection.execute(
            "SELECT COUNT(*) FROM moz_bookmarks b JOIN moz_places p ON p.id = b.fk "
            "WHERE b.type = 1 AND p.url NOT LIKE 'place:%'").fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning(f"Bookmarks unavailable for {profile}: {exc}")
    try:
        downloads = connection.execute(
            "SELECT COUNT(DISTINCT a.place_id) FROM moz_annos a "
            "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
            "WHERE n.name = 'downloads/destinationFileURI'").fetchone()[0]
    except sqlite3.Error as exc:
        logger.warning(f"Download records unavailable for {profile}: {exc}")
    return {"visits": visits, "bookmarks": int(bookmarks or 0), "downloads": int(downloads or 0)}


def _count_extensions(profile_path: str, profile: str, logger: AnalysisLogger) -> int:
    path = os.path.join(profile_path, "extensions.json")
    text, error = read_text_file(path)
    if error:
        if error != "file not found":
            logger.warning(f"extensions.json unavailable for {profile}: {error}")
        return 0
    try:
        import json
        addons = json.loads(text).get("addons")
        return len(addons) if isinstance(addons, list) else 0
    except (ValueError, AttributeError):
        logger.warning(f"extensions.json is not valid JSON for {profile}.")
        return 0


# ============================================================ orchestration
def _analyze_profile(spec: Dict, logger: AnalysisLogger) -> ProfileResult:
    name = spec["directory_name"]
    profile = ProfileResult(directory_name=name, path=spec["path"], windows_user=spec["windows_user"],
                            profile_name=spec["profile_name"], attribution=spec["attribution"],
                            attribution_basis=spec["attribution_basis"])
    logger.info(f"Analyzing profile '{profile.profile_name}' ({name}) [{spec['attribution']}] "
                f"(Windows user: {spec['windows_user']})...")
    profile.extension_count = _count_extensions(spec["path"], name, logger)

    places_path = os.path.join(spec["path"], "places.sqlite")
    if not os.path.isfile(places_path):
        profile.history_status = "Not found"
        logger.warning(f"places.sqlite not found for {name} (unavailable, not proof of no browsing).")
        return profile
    try:
        data, method, digest = _with_database(places_path, logger, lambda c: _read_places(c, name, logger))
    except DatabaseAccessError as exc:
        profile.history_status = f"Unavailable: {exc}"
        logger.warning(f"places.sqlite unavailable for {name}: {exc}")
        return profile

    profile.visits = data["visits"]
    profile.history_db_sha256 = digest
    profile.visit_count = len(profile.visits)
    profile.unique_url_count = len({v.url for v in profile.visits})
    profile.unique_domain_count = len({get_domain(v.url) for v in profile.visits} - {None})
    profile.bookmark_count = data["bookmarks"]
    profile.download_count = data["downloads"]
    profile.history_status = (f"Read OK ({method})" if profile.visits
                              else f"Read OK, no records ({method})")
    logger.info(f"{name}: {profile.visit_count:,} visits, {profile.unique_url_count:,} unique URLs, "
                f"{profile.unique_domain_count:,} unique domains.")
    return profile


def _build_summary(info: BrowserInfo, profiles: List[ProfileResult],
                   unattributed: List[ProfileResult]) -> Dict:
    visits = [v for p in profiles for v in p.visits]
    return {
        "executable_path": info.executable_path,
        "version": info.version,
        "profile_count": len(profiles),
        "profile_names": [p.profile_name for p in profiles],
        "unattributed_profile_count": len(unattributed),
        "unique_url_count": len({v.url for v in visits}),
        "unique_domain_count": len({get_domain(v.url) for v in visits} - {None}),
        "bookmark_count": sum(p.bookmark_count for p in profiles),
        "download_count": sum(p.download_count for p in profiles),
        "extension_count": sum(p.extension_count for p in profiles),
        "total_visits": len(visits),
    }


def _run_analysis(root_drive: str, exe_path: str, logger: AnalysisLogger, result: AnalysisResult) -> None:
    if not root_drive or not os.path.isdir(root_drive):
        logger.error(f"Selected drive is not accessible: {root_drive!r}")
        return
    if not exe_path or not os.path.isfile(exe_path):
        logger.error(f"Firefox executable was not found at the specified location: {exe_path!r}")
        return
    exe_path = os.path.normpath(exe_path)
    logger.info("Starting Firefox analysis (single installation)...")
    info = _build_browser_info(exe_path, root_drive, logger)
    result.browser = info

    specs = _collect_profile_specs(root_drive, exe_path, info, logger)
    mine = [s for s in specs if s["attribution"] in ("confirmed", "inferred")]
    other = [s for s in specs if s["attribution"] == "unattributed"]
    if not mine:
        logger.warning("No profile could be tied to this installation (it may never have been run "
                       "by a user on this drive, or was started with -profile).")
    logger.info(f"Profiles tied to this installation: {len(mine)}; other profiles on the drive: {len(other)}.")

    for spec in mine:
        try:
            result.profiles.append(_analyze_profile(spec, logger))
        except Exception as exc:
            logger.error(f"Profile '{spec['directory_name']}' failed: {exc!r}")
            result.profiles.append(ProfileResult(
                directory_name=spec["directory_name"], path=spec["path"], windows_user=spec["windows_user"],
                profile_name=spec["profile_name"], attribution=spec["attribution"],
                attribution_basis=spec["attribution_basis"], history_status=f"Analysis failed: {exc!r}"))
    for spec in other:   # listed by name only, never analysed
        result.unattributed_profiles.append(ProfileResult(
            directory_name=spec["directory_name"], path=spec["path"], windows_user=spec["windows_user"],
            profile_name=spec["profile_name"], attribution="unattributed",
            attribution_basis=spec["attribution_basis"],
            history_status="Not analyzed (not tied to this installation)"))

    result.summary = _build_summary(info, result.profiles, result.unattributed_profiles)
    logger.info("Analysis completed.")


# ================================================================ public entry points
def analyze_firefox(selected_drive: str, selected_browser: str = "Mozilla Firefox",
                    target_exe_path: Optional[str] = None,
                    log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    """Analyse ONE Firefox installation (target_exe_path) and only its profiles.

    If target_exe_path is None, standard locations are searched and the analysis
    proceeds only when exactly ONE installation is found (installations are never merged)."""
    logger = AnalysisLogger(callback=log_callback)
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
                                 "one to analyse: " + "; ".join(found))
            if exe:
                _run_analysis(selected_drive, exe, logger, result)
    except Exception as exc:
        logger.error(f"Unexpected failure: {exc!r}")
    result.warnings = list(logger.warnings)
    result.errors = list(logger.errors)
    result.log = list(logger.entries)
    result.finished_utc = now_utc_string()
    return result


def analyze_all_firefox_installations(selected_drive: str,
                                      log_callback: Optional[Callable[[str], None]] = None
                                      ) -> List[AnalysisResult]:
    """One INDEPENDENT AnalysisResult per installation found on the drive."""
    exes = discover_firefox_installations(selected_drive) if os.path.isdir(selected_drive or "") else []
    return [analyze_firefox(selected_drive, "Mozilla Firefox", exe, log_callback) for exe in exes]


if __name__ == "__main__":
    # python firefox_analyzer.py D:\\ "D:\\Program Files\\Mozilla Firefox\\firefox.exe"
    import json
    drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    exe_arg = sys.argv[2] if len(sys.argv) > 2 else None
    outcome = analyze_firefox(drive, "Mozilla Firefox", exe_arg, log_callback=print)
    print(json.dumps(outcome.summary, indent=2))
    for row in outcome.websites_visited()[:20]:
        print(row["visit_time"], row["url"])