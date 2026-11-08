# analysis/chrome_analyzer.py
import ctypes
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

@dataclass(frozen=True)
class BrowserSpec:
    name: str
    exe_name: str
    system_install_dirs: tuple
    per_user_install_dirs: tuple
    per_user_data_dir: str

@dataclass
class BrowserLocation:
    name: str
    drive: str
    executable_paths: List[str] = field(default_factory=list)
    user_data_dirs: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class BrowserInfo:
    name: str
    version: Optional[str] = None
    version_source: Optional[str] = None
    executable_path: Optional[str] = None
    installation_path: Optional[str] = None
    executable_exists: bool = False
    user_data_paths: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

@dataclass
class HistoryRecord:
    url: str
    title: str
    visit_time: Optional[str]
    visit_count: int
    profile: str

@dataclass
class HistoryStatistics:
    history_record_count: int = 0
    total_visits: int = 0
    unique_url_count: int = 0
    unique_domain_count: int = 0
    first_visit: Optional[str] = None
    last_visit: Optional[str] = None

@dataclass
<<<<<<< Updated upstream
=======
class DownloadRecord:
    download_id: Optional[int] = None
    guid: str = ""
    file_name: str = ""
    target_path: str = ""
    current_path: str = ""
    url: str = ""
    url_chain: List[str] = field(default_factory=list)
    referrer: str = ""
    site_url: str = ""
    tab_url: str = ""
    tab_referrer_url: str = ""
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    last_access_time: Optional[str] = None
    received_bytes: int = 0
    total_bytes: int = 0
    state: str = "Unknown"
    danger_type: str = "Unknown"
    interrupt_reason: str = "None"
    opened: bool = False
    mime_type: str = ""
    original_mime_type: str = ""
    etag: str = ""
    last_modified: str = ""
    http_method: str = ""
    by_extension: str = ""
    profile: str = ""

@dataclass
class CookieRecord:
    host: str
    name: str
    path: str
    creation_time: Optional[str]
    expiry_time: Optional[str]
    is_secure: bool
    is_httponly: bool
    profile: str

@dataclass
>>>>>>> Stashed changes
class ProfileResult:
    directory_name: str
    path: str
    windows_user: str
    display_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    history_db_path: Optional[str] = None
    history_status: str = "Not analyzed"
    history_db_sha256: Optional[str] = None
    history: List[HistoryRecord] = field(default_factory=list)
    statistics: HistoryStatistics = field(default_factory=HistoryStatistics)
    cookie_count: int = 0
    cookies: List[CookieRecord] = field(default_factory=list)

@dataclass
class AnalysisResult:
    drive: str
    browser: Optional[BrowserInfo] = None
    profiles: List[ProfileResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)
    started_utc: Optional[str] = None
    finished_utc: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def chrome_time_to_datetime(value: Any) -> Optional[datetime]:
    try:
        micros = int(value)
        if micros <= 0:
            return None
        return CHROME_EPOCH + timedelta(microseconds=micros)
    except (TypeError, ValueError, OverflowError):
        return None

def format_utc(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None

def chrome_time_to_string(value: Any) -> Optional[str]:
    return format_utc(chrome_time_to_datetime(value))

def now_utc_string() -> str:
    return format_utc(datetime.now(timezone.utc))

class AnalysisLogger:
    def __init__(self, callback: Optional[Callable[[str], None]] = None):
        self.entries: List[str] = []
        self.warnings: List[str] = []
        self.errors: List[str] = []
        self._callback = callback

    def _emit(self, prefix: str, message: str) -> str:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {prefix}{message}"
        self.entries.append(line)
        if self._callback:
            try:
                self._callback(line)
            except Exception:
                pass
        return line

    def info(self, message: str) -> None:
        self._emit("", message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)
        self._emit("WARNING: ", message)

    def error(self, message: str) -> None:
        self.errors.append(message)
        self._emit("ERROR: ", message)

def read_json_file(path: str) -> Tuple[Optional[dict], Optional[str]]:
    if not os.path.isfile(path):
        return None, "file not found"
    try:
        with open(path, "r", encoding="utf-8-sig") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            return None, "unexpected JSON structure"
        return data, None
    except PermissionError:
        return None, "permission denied"
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON ({exc})"
    except OSError as exc:
        return None, f"cannot be read ({exc})"

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

    return {
        "size_bytes": st.st_size,
        "modified_utc": utc(st.st_mtime),
        "created_utc": utc(st.st_ctime),
    }

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

CHROME_SPEC = BrowserSpec(
    name="Google Chrome",
    exe_name="chrome.exe",
    system_install_dirs=("Program Files/Google/Chrome/Application",
                         "Program Files (x86)/Google/Chrome/Application"),
    per_user_install_dirs=("AppData/Local/Google/Chrome/Application",),
    per_user_data_dir="AppData/Local/Google/Chrome/User Data",
)

SUPPORTED_BROWSERS = [CHROME_SPEC]

SKIPPED_USER_DIRS = {"public", "default", "default user", "all users",
                     "defaultuser0", "desktop.ini"}

PROFILE_DIR_PATTERN = re.compile(r"^(Default|Profile \d+)$", re.IGNORECASE)

class HistoryAccessError(Exception):
    pass

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

def locate_browser(root_drive: str, spec: BrowserSpec,
                   logger: AnalysisLogger) -> Optional[BrowserLocation]:
    executables: List[str] = []
    user_data_dirs: List[Dict[str, str]] = []

    for relative in spec.system_install_dirs:
        candidate = os.path.normpath(os.path.join(root_drive, relative, spec.exe_name))
        if os.path.isfile(candidate):
            executables.append(candidate)

    for user in _list_windows_users(root_drive, logger):
        user_root = os.path.join(root_drive, "Users", user)
        for relative in spec.per_user_install_dirs:
            candidate = os.path.normpath(os.path.join(user_root, relative, spec.exe_name))
            if os.path.isfile(candidate):
                executables.append(candidate)
        data_dir = os.path.normpath(os.path.join(user_root, spec.per_user_data_dir))
        if os.path.isdir(data_dir):
            user_data_dirs.append({"windows_user": user, "path": data_dir})

    if not executables and not user_data_dirs:
        return None
    return BrowserLocation(name=spec.name, drive=root_drive,
                           executable_paths=executables, user_data_dirs=user_data_dirs)

def _version_from_folder(application_dir: str) -> Optional[str]:
    try:
        versions = [name for name in os.listdir(application_dir)
                    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", name)
                    and os.path.isdir(os.path.join(application_dir, name))]
    except OSError:
        return None
    if not versions:
        return None
    return max(versions, key=lambda v: tuple(int(p) for p in v.split(".")))

def _build_browser_info(location: BrowserLocation, logger: AnalysisLogger) -> BrowserInfo:
    info = BrowserInfo(name=location.name,
                       user_data_paths=[d["path"] for d in location.user_data_dirs])

    if not location.executable_paths:
        info.notes.append("Executable not found; browser may be uninstalled or in a "
                          "non-standard location. User data was still found.")
        logger.warning("Chrome executable not found (data directory only).")
        return info

    exe = location.executable_paths[0]
    info.executable_path = exe
    info.executable_exists = os.path.isfile(exe)
    info.installation_path = os.path.dirname(exe)
    logger.info(f"Chrome executable found: {exe}")
    if len(location.executable_paths) > 1:
        others = "; ".join(location.executable_paths[1:])
        info.notes.append(f"Additional installations found: {others}")
        logger.warning(f"Multiple Chrome installations found; reporting the first. Others: {others}")

    version = get_file_version(exe)
    if version:
        info.version, info.version_source = version, "executable version resource"
    else:
        folder_version = _version_from_folder(info.installation_path)
        if folder_version:
            info.version, info.version_source = folder_version, "version folder name"
    if info.version:
        logger.info(f"Chrome version: {info.version} ({info.version_source})")
    else:
        logger.warning("Chrome version could not be determined.")
    return info

def _profile_sort_key(name: str) -> Tuple[int, int, str]:
    if name.lower() == "default":
        return (0, 0, name)
    match = re.fullmatch(r"Profile (\d+)", name, re.IGNORECASE)
    if match:
        return (1, int(match.group(1)), name)
    return (2, 0, name)

def _discover_profiles(windows_user: str, user_data_path: str,
                       logger: AnalysisLogger) -> List[Dict]:
    local_state, error = read_json_file(os.path.join(user_data_path, "Local State"))
    if error:
        logger.warning(f"'Local State' unavailable for user '{windows_user}': {error}")
    info_cache = dig(local_state, "profile", "info_cache")
    if not isinstance(info_cache, dict):
        info_cache = {}

    names = set(info_cache.keys())
    try:
        with os.scandir(user_data_path) as entries:
            for entry in entries:
                try:
                    if entry.is_dir() and PROFILE_DIR_PATTERN.match(entry.name):
                        names.add(entry.name)
                except OSError:
                    logger.warning(f"Cannot inspect {entry.path}")
    except OSError as exc:
        logger.warning(f"Unable to list {user_data_path}: {exc}")

    profiles = []
    for name in sorted(names, key=_profile_sort_key):
        path = os.path.join(user_data_path, name)
        if not os.path.isdir(path):
            logger.warning(f"Profile '{name}' is listed in Local State but its folder was not found.")
            continue
        if not (os.path.isfile(os.path.join(path, "Preferences"))
                or os.path.isfile(os.path.join(path, "History"))):
            logger.warning(f"'{name}' skipped: no Preferences or History file (not a valid profile).")
            continue
        profiles.append({"directory_name": name, "path": path,
                         "windows_user": windows_user,
                         "local_state_entry": info_cache.get(name)})
    return profiles

def _read_profile_metadata(spec: Dict, profile: ProfileResult, logger: AnalysisLogger) -> None:
    metadata = profile.metadata
    metadata["windows_user"] = spec["windows_user"]

    cache = spec.get("local_state_entry")
    if isinstance(cache, dict):
        profile.display_name = cache.get("name") or None
        metadata["local_state_name"] = cache.get("name")
        active = cache.get("active_time")
        if isinstance(active, (int, float)):
            try:
                metadata["last_active_utc"] = format_utc(
                    datetime.fromtimestamp(active, tz=timezone.utc))
            except (OverflowError, OSError, ValueError):
                pass
        metadata["account_info_present"] = bool(cache.get("user_name") or cache.get("gaia_name"))

    prefs_path = os.path.join(spec["path"], "Preferences")
    prefs, error = read_json_file(prefs_path)
    if error:
        logger.warning(f"Preferences unavailable for {profile.directory_name}: {error}")
        metadata["preferences_status"] = f"unavailable ({error})"
    else:
        metadata["preferences_status"] = "read"
        name = dig(prefs, "profile", "name")
        if name:
            metadata["preferences_profile_name"] = name
            profile.display_name = profile.display_name or name
        languages = dig(prefs, "intl", "accept_languages")
        if languages:
            metadata["accept_languages"] = languages
        download_dir = dig(prefs, "download", "default_directory")
        if download_dir:
            metadata["download_default_directory"] = download_dir
        created = chrome_time_to_string(dig(prefs, "profile", "creation_time"))
        if created:
            metadata["profile_creation_time"] = created

    for label, filename in (("preferences_file", "Preferences"), ("history_file", "History")):
        details = file_metadata(os.path.join(spec["path"], filename))
        if details:
            metadata[label] = details

def _open_history(history_path: str, temp_dir: str,
                  logger: AnalysisLogger) -> Tuple[sqlite3.Connection, str, Optional[str]]:
    copy_path = os.path.join(temp_dir, "History")
    try:
        shutil.copyfile(history_path, copy_path)
        for suffix in ("-wal", "-journal"):
            side_file = history_path + suffix
            if os.path.isfile(side_file):
                shutil.copyfile(side_file, copy_path + suffix)
        return sqlite3.connect(copy_path), "temporary copy", sha256_file(copy_path)
    except OSError as exc:
        logger.warning(f"Could not copy History database ({exc}); is Chrome running? "
                       "Trying read-only direct access (recent entries may be missing).")

    try:
        uri = Path(history_path).as_uri() + "?mode=ro&immutable=1"
        return sqlite3.connect(uri, uri=True), "direct read-only (immutable)", None
    except sqlite3.Error as exc:
        raise HistoryAccessError(f"database locked or inaccessible ({exc})")

<<<<<<< Updated upstream

def read_history_database(history_path: str, profile_name: str,
                          logger: AnalysisLogger
                          ) -> Tuple[List[HistoryRecord], Optional[str], str, Optional[str]]:
    """Read Chrome's 'urls' table. Returns (records, first_visit, method, sha256).

    One record per distinct URL; visit_time is that URL's most recent visit.
    """
=======
DOWNLOAD_STATES = {0: "In progress", 1: "Complete", 2: "Cancelled",
                   3: "Interrupted", 4: "Dangerous"}

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

def _enum_label(mapping: Dict[int, str], value: Any) -> str:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return "Unknown"
    return mapping.get(number, f"Unknown ({number})")

def _download_file_name(target: str, current: str, url: str) -> str:
    for path in (target, current):
        if path:
            name = ntpath.basename(path)
            if name:
                return name
    try:
        name = os.path.basename(urlparse(url).path)
    except ValueError:
        name = ""
    return name or "(unknown)"

def read_downloads(connection: sqlite3.Connection, profile_name: str,
                   logger: AnalysisLogger) -> List[DownloadRecord]:
    try:
        available = {row[1] for row in connection.execute("PRAGMA table_info(downloads)")}
    except sqlite3.Error as exc:
        logger.warning(f"Could not inspect downloads table for {profile_name}: {exc}")
        return []
    if not available:
        logger.info(f"{profile_name}: no 'downloads' table in History database.")
        return []

    columns = [c for c in _DOWNLOAD_COLUMNS if c in available]
    query = f"SELECT {', '.join(columns)} FROM downloads"
    if "start_time" in available:
        query += " ORDER BY start_time DESC"

    chains: Dict[int, List[str]] = {}
    try:
        for dl_id, url in connection.execute(
                "SELECT id, url FROM downloads_url_chains ORDER BY id, chain_index"):
            chains.setdefault(dl_id, []).append(url or "")
    except sqlite3.Error:
        logger.warning(f"'downloads_url_chains' unavailable for {profile_name}; "
                       "download source URLs may be missing.")

    records: List[DownloadRecord] = []
    try:
        for values in connection.execute(query):
            row = dict(zip(columns, values))
            chain = chains.get(row.get("id"), [])
            target = row.get("target_path") or ""
            current = row.get("current_path") or ""
            url = chain[-1] if chain else ""
            records.append(DownloadRecord(
                download_id=row.get("id"),
                guid=row.get("guid") or "",
                file_name=_download_file_name(target, current, url),
                target_path=target,
                current_path=current,
                url=url,
                url_chain=chain,
                referrer=row.get("referrer") or "",
                site_url=row.get("site_url") or "",
                tab_url=row.get("tab_url") or "",
                tab_referrer_url=row.get("tab_referrer_url") or "",
                start_time=chrome_time_to_string(row.get("start_time")),
                end_time=chrome_time_to_string(row.get("end_time")),
                last_access_time=chrome_time_to_string(row.get("last_access_time")),
                received_bytes=int(row.get("received_bytes") or 0),
                total_bytes=int(row.get("total_bytes") or 0),
                state=_enum_label(DOWNLOAD_STATES, row.get("state")),
                danger_type=_enum_label(DANGER_TYPES, row.get("danger_type")),
                interrupt_reason=_enum_label(INTERRUPT_REASONS, row.get("interrupt_reason")),
                opened=bool(row.get("opened")),
                mime_type=row.get("mime_type") or "",
                original_mime_type=row.get("original_mime_type") or "",
                etag=row.get("etag") or "",
                last_modified=row.get("last_modified") or "",
                http_method=row.get("http_method") or "",
                by_extension=row.get("by_ext_name") or "",
                profile=profile_name,
            ))
    except sqlite3.Error as exc:
        logger.warning(f"Downloads could not be fully read for {profile_name}: {exc}")
    return records

def read_history_database(history_path: str, profile_name: str,
                          logger: AnalysisLogger
                          ) -> Tuple[List[HistoryRecord], Optional[str], str, Optional[str],
                                     List[DownloadRecord]]:
>>>>>>> Stashed changes
    temp_dir = tempfile.mkdtemp(prefix="bfa_")
    try:
        connection, method, sha256 = _open_history(history_path, temp_dir, logger)
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        records: List[HistoryRecord] = []
        first_visit: Optional[str] = None
        try:
            cursor = connection.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls "
                "ORDER BY last_visit_time DESC")
            for url, title, visit_count, last_visit_time in cursor:
                records.append(HistoryRecord(
                    url=url or "", title=title or "",
                    visit_time=chrome_time_to_string(last_visit_time),
                    visit_count=int(visit_count or 0), profile=profile_name))
            try:
                row = connection.execute(
                    "SELECT MIN(visit_time) FROM visits WHERE visit_time > 0").fetchone()
                first_visit = chrome_time_to_string(row[0]) if row else None
            except sqlite3.Error:
                logger.warning(f"'visits' table unavailable for {profile_name}; "
                               "first visit estimated from URL records.")
        except sqlite3.DatabaseError as exc:
            raise HistoryAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
        return records, first_visit, method, sha256
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def read_cookies_database(cookies_path: str, profile_name: str, logger: AnalysisLogger) -> Tuple[List[CookieRecord], str, Optional[str]]:
    temp_dir = tempfile.mkdtemp(prefix="bfa_c_")
    try:
        connection, method, sha256 = _open_history(cookies_path, temp_dir, logger)
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        records = []
        try:
            for host, name, path, creation, expires, secure, httponly in connection.execute(
                    "SELECT host_key, name, path, creation_utc, expires_utc, is_secure, is_httponly FROM cookies"):
                records.append(CookieRecord(
                    host=host or "", name=name or "", path=path or "",
                    creation_time=chrome_time_to_string(creation),
                    expiry_time=chrome_time_to_string(expires),
                    is_secure=bool(secure), is_httponly=bool(httponly), profile=profile_name
                ))
        except sqlite3.DatabaseError as exc:
            raise HistoryAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
        return records, method, sha256
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def compute_statistics(records: List[HistoryRecord],
                       first_visit: Optional[str] = None) -> HistoryStatistics:
    times = [r.visit_time for r in records if r.visit_time]
    domains = {get_domain(r.url) for r in records} - {None}
    return HistoryStatistics(
        history_record_count=len(records),
        total_visits=sum(r.visit_count for r in records),
        unique_url_count=len({r.url for r in records}),
        unique_domain_count=len(domains),
        first_visit=first_visit or (min(times) if times else None),
        last_visit=max(times) if times else None,
    )

def _analyze_profile(spec: Dict, logger: AnalysisLogger) -> ProfileResult:
    name = spec["directory_name"]
    profile = ProfileResult(directory_name=name, path=spec["path"],
                            windows_user=spec["windows_user"])
    logger.info(f"Analyzing {name} profile (Windows user: {spec['windows_user']})...")
    _read_profile_metadata(spec, profile, logger)

    history_path = os.path.join(spec["path"], "History")
    if not os.path.isfile(history_path):
        profile.history_status = "Not found"
        logger.warning(f"History database not found for {name} (unavailable, not proof of no browsing).")
<<<<<<< Updated upstream
        return profile

    profile.history_db_path = history_path
    logger.info("History database found. Reading history...")
    try:
        records, first_visit, method, sha256 = read_history_database(history_path, name, logger)
    except HistoryAccessError as exc:
        profile.history_status = f"Unavailable: {exc}"
        logger.warning(f"History database unavailable for {name}: {exc}")
        return profile

    profile.history = records
    profile.history_db_sha256 = sha256
    profile.statistics = compute_statistics(records, first_visit)
    if records:
        profile.history_status = f"Read OK ({method})"
        logger.info(f"{name}: {len(records):,} history records, "
                    f"{profile.statistics.unique_domain_count:,} unique domains.")
=======
>>>>>>> Stashed changes
    else:
        profile.history_db_path = history_path
        logger.info("History database found. Reading history...")
        try:
            records, first_visit, method, sha256, downloads = read_history_database(
                history_path, name, logger)
            profile.history = records
            profile.downloads = downloads
            logger.info(f"{name}: {len(downloads):,} download record(s).")
            profile.history_db_sha256 = sha256
            profile.statistics = compute_statistics(records, first_visit)
            if records:
                profile.history_status = f"Read OK ({method})"
                logger.info(f"{name}: {len(records):,} history records, "
                            f"{profile.statistics.unique_domain_count:,} unique domains.")
            else:
                profile.history_status = f"Read OK, no records ({method})"
                logger.info(f"{name}: History database contains no records.")
        except HistoryAccessError as exc:
            profile.history_status = f"Unavailable: {exc}"
            logger.warning(f"History database unavailable for {name}: {exc}")

    cookies_paths = [os.path.join(spec["path"], "Network", "Cookies"), os.path.join(spec["path"], "Cookies")]
    cookies_path = next((p for p in cookies_paths if os.path.isfile(p)), None)
    if cookies_path:
        try:
            c_records, c_method, c_sha256 = read_cookies_database(cookies_path, name, logger)
            profile.cookies = c_records
            profile.cookie_count = len(c_records)
            logger.info(f"{name}: {profile.cookie_count:,} cookies found.")
        except HistoryAccessError as exc:
            logger.warning(f"Cookies database unavailable for {name}: {exc}")

    return profile

def _build_summary(profiles: List[ProfileResult]) -> Dict:
    all_records = [r for p in profiles for r in p.history]
    stats = compute_statistics(all_records)
    firsts = [p.statistics.first_visit for p in profiles if p.statistics.first_visit]
    return {
        "profile_count": len(profiles),
        "profiles_with_history": sum(1 for p in profiles if p.history_status.startswith("Read OK")),
        "windows_users": sorted({p.windows_user for p in profiles}),
        "history_record_count": stats.history_record_count,
        "total_visits": stats.total_visits,
        "unique_url_count": stats.unique_url_count,
        "unique_domain_count": stats.unique_domain_count,
        "first_visit": min(firsts) if firsts else None,
        "last_visit": stats.last_visit,
<<<<<<< Updated upstream
=======
        "download_count": sum(len(p.downloads) for p in profiles),
        "cookie_count": sum(p.cookie_count for p in profiles),
>>>>>>> Stashed changes
    }

def _locate_specific_browser(root_drive: str, exe_path: str, spec: BrowserSpec, logger: AnalysisLogger) -> BrowserLocation:
    executables = [exe_path] if os.path.isfile(exe_path) else []
    user_data_dirs = []

    exe_dir = os.path.dirname(exe_path)
    adjacent_data = os.path.join(exe_dir, "User Data")
    
    if os.path.isdir(adjacent_data):
        user_data_dirs.append({"windows_user": "portable/adjacent", "path": adjacent_data})
        logger.info(f"Adjacent User Data directory found at {adjacent_data}")

    for user in _list_windows_users(root_drive, logger):
        user_root = os.path.join(root_drive, "Users", user)
        data_dir = os.path.normpath(os.path.join(user_root, spec.per_user_data_dir))
        if os.path.isdir(data_dir):
            user_data_dirs.append({"windows_user": user, "path": data_dir})

    return BrowserLocation(
        name=spec.name, 
        drive=root_drive,
        executable_paths=executables, 
        user_data_dirs=user_data_dirs
    )

def _run_analysis(root_drive: str, target_exe_path: Optional[str],
                  logger: AnalysisLogger, result: AnalysisResult) -> None:
    if not root_drive or not os.path.isdir(root_drive):
        logger.error(f"Selected drive is not accessible: {root_drive!r}")
        return

    logger.info("Starting Chrome analysis...")
    
    if target_exe_path:
        location = _locate_specific_browser(root_drive, target_exe_path, CHROME_SPEC, logger)
    else:
        location = locate_browser(root_drive, CHROME_SPEC, logger)

    if location is None or not location.executable_paths:
        logger.error("Google Chrome was not found at the specified location.")
        return

    result.browser = _build_browser_info(location, logger)

    if not location.user_data_dirs:
        logger.warning("No Chrome 'User Data' directory found; no profiles to analyze.")
        
    profile_specs: List[Dict] = []
    for entry in location.user_data_dirs:
        logger.info(f"User Data directory found: {entry['path']}")
        profile_specs.extend(_discover_profiles(entry["windows_user"], entry["path"], logger))
    logger.info(f"Found {len(profile_specs)} profile(s).")

    for spec in profile_specs:
        try:
            result.profiles.append(_analyze_profile(spec, logger))
        except Exception as exc:
            logger.error(f"Profile '{spec['directory_name']}' failed: {exc!r}")
            result.profiles.append(ProfileResult(
                directory_name=spec["directory_name"], path=spec["path"],
                windows_user=spec["windows_user"],
                history_status=f"Analysis failed: {exc!r}"))

    result.summary = _build_summary(result.profiles)
    logger.info("Analysis completed.")

SUPPORTED_BROWSER_NAMES = {"google chrome", "chrome"}

def analyze_chrome(selected_drive: str, selected_browser: str = "Google Chrome",
                   target_exe_path: Optional[str] = None,
                   log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    logger = AnalysisLogger(callback=log_callback)
    result = AnalysisResult(drive=selected_drive, started_utc=now_utc_string())
    try:
        if not selected_drive or not selected_browser:
            logger.error("A drive and a browser must both be selected.")
        elif selected_browser.strip().lower() not in SUPPORTED_BROWSER_NAMES:
            logger.error(f"'{selected_browser}' is not supported yet (only Google Chrome).")
        else:
            _run_analysis(selected_drive, target_exe_path, logger, result)
    except Exception as exc:
        logger.error(f"Unexpected failure: {exc!r}")
    result.warnings = list(logger.warnings)
    result.errors = list(logger.errors)
    result.log = list(logger.entries)
    result.finished_utc = now_utc_string()
    return result

if __name__ == "__main__":
    drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    outcome = analyze_chrome(drive, "Google Chrome", log_callback=print)
    print(json.dumps(outcome.summary, indent=2))