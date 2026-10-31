"""
brave_analyzer.py  --  standalone Brave browser analysis engine (per installation).

    from brave_analyzer import analyze_brave

    result = analyze_brave(selected_drive, selected_browser, target_exe_path,
                           log_callback=None)

    selected_drive   : e.g. "D:\\"
    selected_browser : "Brave" (also "Brave Browser", "Brave Beta", "Brave Nightly", "Brave Dev")
    target_exe_path  : full path of the EXACT brave.exe to analyse,
                       e.g. "D:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    log_callback     : optional function(str) receiving each log line live

It never raises; failures are in result.errors / result.warnings.

WHAT IT REPORTS (only for the installation given in target_exe_path)
    result.summary["profile_count"], ["profile_names"]
    result.summary["unique_url_count"], ["unique_domain_count"], ["bookmark_count"],
                   ["download_count"], ["extension_count"], ["total_visits"]
    result.websites_visited()   -> every website visit with its time (newest first)
    result.profiles[i]          -> per-profile name, path and the same counts / visits

HOW PROFILES ARE TIED TO THE INSTALLATION
    Unlike Firefox, Chromium browsers keep NO link between an installation and a
    profile. Profiles live in a "User Data" folder that is chosen by CHANNEL and USER:
        ...\\BraveSoftware\\Brave-Browser\\User Data          (release)
        ...\\BraveSoftware\\Brave-Browser-Beta\\User Data     (Beta), -Nightly, -Dev
    So the exe path decides:
      * channel   : taken from the install folder name (Brave-Browser / -Beta / ...),
                    so a Beta install never reports release profiles and vice versa.
      * owner     : an install inside Users\\<name>\\... is a per-user install, so only
                    that user's data is read; a system-wide install (Program Files)
                    reads every user's data folder for that channel.
      * portable  : a "User Data" folder next to the exe is used on its own.
    LIMIT: two installs of the SAME channel for the same user (e.g. system-wide and
    per-user) share one User Data folder and cannot be separated by any method; the
    analyzer logs a warning when it detects this.

Forensic handling: paths derive from selected_drive only; the History database is
COPIED (with its -journal/-wal) to a temp folder and the copy is queried; nothing is
written to the source drive; Brave is never launched. A missing artifact is reported
as unavailable, never as proof of non-use.
"""

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


# ================================================================== models
@dataclass
class BrowserInfo:
    name: str
    channel: Optional[str] = None               # e.g. "Brave-Browser", "Brave-Browser-Beta"
    version: Optional[str] = None
    executable_path: Optional[str] = None
    installation_path: Optional[str] = None
    executable_exists: bool = False
    install_scope: Optional[str] = None         # "system-wide" | "per-user (<name>)" | "portable"
    user_data_paths: List[str] = field(default_factory=list)


@dataclass
class VisitRecord:
    url: str
    title: str
    visit_time: Optional[str]       # UTC
    profile: str


@dataclass
class ProfileResult:
    directory_name: str                         # "Default", "Profile 1", ...
    path: str
    windows_user: str
    profile_name: str = ""                      # name shown in Brave (e.g. "Person 1")
    attribution_basis: str = ""
    history_status: str = "Not analyzed"
    history_db_sha256: Optional[str] = None     # hash of the analysed copy of History
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
    profiles: List[ProfileResult] = field(default_factory=list)   # THIS installation only
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
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)   # Chromium time base


def format_utc(dt: Optional[datetime]) -> Optional[str]:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None


def chrome_time_to_string(value: Any) -> Optional[str]:
    """Chromium timestamp: microseconds since 1601-01-01 UTC. None if invalid."""
    try:
        micros = int(value)
        if micros <= 0:
            return None
        return format_utc(CHROME_EPOCH + timedelta(microseconds=micros))
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


# ============================================================ locating
BRAVE_VENDOR_DIR = "BraveSoftware"
EXE_NAME = "brave.exe"
CHANNELS = ("Brave-Browser", "Brave-Browser-Beta", "Brave-Browser-Nightly", "Brave-Browser-Dev")

SUPPORTED_BROWSER_NAMES = {"brave", "brave browser", "brave-browser", "brave beta", "brave nightly",
                           "brave dev", "brave-browser-beta", "brave-browser-nightly", "brave-browser-dev"}

SKIPPED_USER_DIRS = {"public", "default", "default user", "all users", "defaultuser0", "desktop.ini"}
PROFILE_DIR_PATTERN = re.compile(r"^(Default|Profile \d+)$", re.IGNORECASE)


class HistoryAccessError(Exception):
    """The History database could not be read (locked, corrupt, ...)."""


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


def discover_brave_installations(root_drive: str, logger: Optional[AnalysisLogger] = None) -> List[str]:
    """brave.exe paths found in standard locations (for a GUI dropdown)."""
    logger = logger or AnalysisLogger()
    found: List[str] = []
    for program_dir in ("Program Files", "Program Files (x86)"):
        for channel in CHANNELS:
            candidate = os.path.normpath(os.path.join(
                root_drive, program_dir, BRAVE_VENDOR_DIR, channel, "Application", EXE_NAME))
            if os.path.isfile(candidate):
                found.append(candidate)
    for user in _list_windows_users(root_drive, logger):
        for channel in CHANNELS:
            candidate = os.path.normpath(os.path.join(
                root_drive, "Users", user, "AppData", "Local", BRAVE_VENDOR_DIR, channel,
                "Application", EXE_NAME))
            if os.path.isfile(candidate):
                found.append(candidate)
    return found


def _detect_channel(exe_path: str) -> Optional[str]:
    """Channel folder name taken from the exe path, e.g. 'Brave-Browser-Beta'."""
    for part in reversed(Path(exe_path.replace("\\", "/")).parts):
        for channel in CHANNELS:
            if part.lower() == channel.lower():
                return channel
    return None


def _install_owner(exe_path: str, root_drive: str) -> Optional[str]:
    """Windows user that owns a per-user install (exe under Users\\<name>\\), else None."""
    try:
        parts = Path(os.path.relpath(exe_path, root_drive)).parts
    except ValueError:
        return None
    if len(parts) > 2 and parts[0].lower() == "users":
        return parts[1]
    return None


def _version_from_folder(application_dir: str) -> Optional[str]:
    """Brave keeps a folder named like 1.81.131 / 140.1.82.166 next to brave.exe."""
    try:
        versions = [n for n in os.listdir(application_dir)
                    if re.fullmatch(r"\d+(\.\d+){2,3}", n) and os.path.isdir(os.path.join(application_dir, n))]
    except OSError:
        return None
    return max(versions, key=lambda v: tuple(int(p) for p in v.split("."))) if versions else None


def _build_browser_info(exe_path: str, root_drive: str, logger: AnalysisLogger) -> BrowserInfo:
    info = BrowserInfo(name="Brave", executable_path=exe_path, executable_exists=os.path.isfile(exe_path),
                       installation_path=os.path.dirname(exe_path), channel=_detect_channel(exe_path))
    logger.info(f"Brave executable found: {exe_path}")
    if os.path.basename(exe_path).lower() != EXE_NAME:
        logger.warning(f"Executable is not named {EXE_NAME}; analysing anyway.")
    info.version = _version_from_folder(info.installation_path)
    if info.version:
        logger.info(f"Brave version: {info.version}")
    return info


# ============================================================ profile discovery
def _profile_sort_key(name: str) -> Tuple[int, int, str]:
    if name.lower() == "default":
        return (0, 0, name)
    m = re.fullmatch(r"Profile (\d+)", name, re.IGNORECASE)
    return (1, int(m.group(1)), name) if m else (2, 0, name)


def _discover_profiles(windows_user: str, user_data_path: str, basis: str,
                       logger: AnalysisLogger) -> List[Dict]:
    """Valid profile folders inside one 'User Data' directory (Local State + Default/Profile N).
    A folder counts only if it holds a 'Preferences' or 'History' file."""
    local_state, error = read_json_file(os.path.join(user_data_path, "Local State"))
    if error:
        logger.warning(f"'Local State' unavailable for '{windows_user}': {error}")
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
        if not (os.path.isfile(os.path.join(path, "Preferences")) or os.path.isfile(os.path.join(path, "History"))):
            logger.warning(f"'{name}' skipped: no Preferences or History file (not a valid profile).")
            continue
        cache = info_cache.get(name)
        profiles.append({"directory_name": name, "path": path, "windows_user": windows_user,
                         "cache_name": cache.get("name") if isinstance(cache, dict) else None,
                         "basis": basis})
    return profiles


def _locate_user_data(root_drive: str, exe_path: str, info: BrowserInfo,
                      logger: AnalysisLogger) -> List[Tuple[str, str, str]]:
    """Return [(windows_user, user_data_path, basis)] belonging to THIS installation."""
    exe_dir = os.path.dirname(exe_path)
    candidates = [os.path.join(exe_dir, "User Data")]
    # ...\\Brave-Browser\\User Data is the STANDARD per-user location, not a portable layout
    if BRAVE_VENDOR_DIR.lower() not in exe_path.replace("\\", "/").lower():
        candidates.append(os.path.join(os.path.dirname(exe_dir), "User Data"))
    for portable in candidates:
        if os.path.isdir(portable):
            info.install_scope = "portable"
            logger.info(f"Portable/adjacent User Data found: {portable}")
            return [("portable/adjacent", portable, "User Data folder located next to the executable")]

    channel = info.channel
    if not channel:
        channel = "Brave-Browser"
        logger.warning("Install channel not recognised from the path; assuming release 'Brave-Browser'.")
        info.channel = channel
    owner = _install_owner(exe_path, root_drive)
    if owner:
        info.install_scope = f"per-user ({owner})"
        users = [owner]
    else:
        info.install_scope = "system-wide"
        users = _list_windows_users(root_drive, logger)

    found = []
    for user in users:
        data_dir = os.path.normpath(os.path.join(root_drive, "Users", user, "AppData", "Local",
                                                 BRAVE_VENDOR_DIR, channel, "User Data"))
        if os.path.isdir(data_dir):
            found.append((user, data_dir, f"{channel} User Data of user '{user}' "
                                          f"({info.install_scope} install)"))

    # Chromium cannot separate two installs of the same channel that share a User Data folder.
    others = [e for e in discover_brave_installations(root_drive)
              if os.path.normcase(e) != os.path.normcase(exe_path) and _detect_channel(e) == channel]
    for other in others:
        other_owner = _install_owner(other, root_drive)
        if owner is None or other_owner is None or other_owner == owner:
            logger.warning(f"Another '{channel}' installation exists ({other}). Chromium gives both the "
                           "same User Data folder, so the profiles below are shared by both installations "
                           "and cannot be separated.")
            break
    return found


# ============================================================ database access
def _with_history(source: str, logger: AnalysisLogger,
                  reader: Callable[[sqlite3.Connection], Any]) -> Tuple[Any, str, Optional[str]]:
    """Run reader on a COPY of the History database (plus -journal / -wal)."""
    temp_dir = tempfile.mkdtemp(prefix="bfa_brave_")
    try:
        copy_path = os.path.join(temp_dir, "History")
        connection: Optional[sqlite3.Connection] = None
        digest: Optional[str] = None
        method = ""
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
            logger.warning(f"Could not copy History database ({exc}); is Brave running? Trying read-only "
                           "direct access (recent entries may be missing).")
        if connection is None:
            try:
                uri = Path(source).resolve().as_uri() + "?mode=ro&immutable=1"
                connection, method = sqlite3.connect(uri, uri=True), "direct read-only (immutable)"
            except sqlite3.Error as exc:
                raise HistoryAccessError(f"database locked or inaccessible ({exc})")
        connection.text_factory = lambda raw: raw.decode("utf-8", errors="replace")
        try:
            return reader(connection), method, digest
        except sqlite3.DatabaseError as exc:
            raise HistoryAccessError(f"database corrupted or locked ({exc})")
        finally:
            connection.close()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)   # removes only OUR temp copy


def _columns(connection: sqlite3.Connection, table: str) -> set:
    try:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _read_history(connection: sqlite3.Connection, profile: str, logger: AnalysisLogger) -> Dict[str, Any]:
    """Visits (one row per visit, with time) plus the download count.

    Hidden URLs and sub-frame visits (transition types 4 and 5) are excluded, matching
    what Brave's own History page shows."""
    url_cols = _columns(connection, "urls")
    has_visits = bool(_columns(connection, "visits"))
    hidden = " AND u.hidden = 0" if "hidden" in url_cols else ""
    visits: List[VisitRecord] = []

    if has_visits:
        for url, title, when in connection.execute(
                "SELECT u.url, u.title, v.visit_time FROM visits v JOIN urls u ON u.id = v.url "
                f"WHERE (v.transition & 255) NOT IN (4, 5){hidden}"):
            visits.append(VisitRecord(url or "", title or "", chrome_time_to_string(when), profile))
    else:
        logger.warning(f"'visits' table unavailable for {profile}; using last-visit times only.")
    # URLs with a visit counter but no individual visit rows
    extra = ("SELECT u.url, u.title, u.last_visit_time FROM urls u WHERE u.visit_count > 0" + hidden)
    if has_visits:
        extra += " AND u.id NOT IN (SELECT url FROM visits)"
    for url, title, when in connection.execute(extra):
        visits.append(VisitRecord(url or "", title or "", chrome_time_to_string(when), profile))
    visits.sort(key=lambda v: v.visit_time or "", reverse=True)

    downloads = 0
    try:
        downloads = int(connection.execute("SELECT COUNT(*) FROM downloads").fetchone()[0] or 0)
    except sqlite3.Error as exc:
        logger.warning(f"Download records unavailable for {profile}: {exc}")
    return {"visits": visits, "downloads": downloads}


def _count_bookmarks(profile_path: str, profile: str, logger: AnalysisLogger) -> int:
    data, error = read_json_file(os.path.join(profile_path, "Bookmarks"))
    if error:
        if error != "file not found":
            logger.warning(f"Bookmarks unavailable for {profile}: {error}")
        return 0

    def count(node: Any) -> int:
        if not isinstance(node, dict):
            return 0
        if node.get("type") == "url":
            return 1
        return sum(count(child) for child in node.get("children", []) or [])

    roots = dig(data, "roots")
    if not isinstance(roots, dict):
        return 0
    return sum(count(node) for node in roots.values())


def _read_preferences(profile_path: str, profile: str, logger: AnalysisLogger) -> Tuple[Optional[str], int]:
    """(profile name from Preferences, number of entries in extensions.settings)."""
    prefs, error = read_json_file(os.path.join(profile_path, "Preferences"))
    if error:
        logger.warning(f"Preferences unavailable for {profile}: {error}")
        return None, 0
    settings = dig(prefs, "extensions", "settings")
    count = sum(1 for value in settings.values() if isinstance(value, dict)) if isinstance(settings, dict) else 0
    return dig(prefs, "profile", "name") or None, count


# ============================================================ orchestration
def _analyze_profile(spec: Dict, logger: AnalysisLogger) -> ProfileResult:
    directory = spec["directory_name"]
    prefs_name, extension_count = _read_preferences(spec["path"], directory, logger)
    profile = ProfileResult(directory_name=directory, path=spec["path"], windows_user=spec["windows_user"],
                            profile_name=spec["cache_name"] or prefs_name or directory,
                            attribution_basis=spec["basis"], extension_count=extension_count)
    logger.info(f"Analyzing profile '{profile.profile_name}' ({directory}) "
                f"(Windows user: {spec['windows_user']})...")
    profile.bookmark_count = _count_bookmarks(spec["path"], directory, logger)

    history_path = os.path.join(spec["path"], "History")
    if not os.path.isfile(history_path):
        profile.history_status = "Not found"
        logger.warning(f"History database not found for {directory} (unavailable, not proof of no browsing).")
        return profile
    try:
        data, method, digest = _with_history(history_path, logger, lambda c: _read_history(c, directory, logger))
    except HistoryAccessError as exc:
        profile.history_status = f"Unavailable: {exc}"
        logger.warning(f"History database unavailable for {directory}: {exc}")
        return profile

    profile.visits = data["visits"]
    profile.history_db_sha256 = digest
    profile.download_count = data["downloads"]
    profile.visit_count = len(profile.visits)
    profile.unique_url_count = len({v.url for v in profile.visits})
    profile.unique_domain_count = len({get_domain(v.url) for v in profile.visits} - {None})
    profile.history_status = f"Read OK ({method})" if profile.visits else f"Read OK, no records ({method})"
    logger.info(f"{directory}: {profile.visit_count:,} visits, {profile.unique_url_count:,} unique URLs, "
                f"{profile.unique_domain_count:,} unique domains.")
    return profile


def _build_summary(info: BrowserInfo, profiles: List[ProfileResult]) -> Dict:
    visits = [v for p in profiles for v in p.visits]
    return {
        "executable_path": info.executable_path,
        "version": info.version,
        "channel": info.channel,
        "install_scope": info.install_scope,
        "profile_count": len(profiles),
        "profile_names": [p.profile_name for p in profiles],
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
        logger.error(f"Brave executable was not found at the specified location: {exe_path!r}")
        return
    exe_path = os.path.normpath(exe_path)
    logger.info("Starting Brave analysis (single installation)...")
    info = _build_browser_info(exe_path, root_drive, logger)
    result.browser = info

    locations = _locate_user_data(root_drive, exe_path, info, logger)
    if not locations:
        logger.warning("No Brave 'User Data' directory found for this installation; no profiles to analyze.")
    specs: List[Dict] = []
    for user, path, basis in locations:
        logger.info(f"User Data directory found: {path}")
        info.user_data_paths.append(path)
        specs.extend(_discover_profiles(user, path, basis, logger))
    logger.info(f"Found {len(specs)} profile(s) for this installation.")

    for spec in specs:
        try:
            result.profiles.append(_analyze_profile(spec, logger))
        except Exception as exc:
            logger.error(f"Profile '{spec['directory_name']}' failed: {exc!r}")
            result.profiles.append(ProfileResult(
                directory_name=spec["directory_name"], path=spec["path"], windows_user=spec["windows_user"],
                profile_name=spec["cache_name"] or spec["directory_name"], attribution_basis=spec["basis"],
                history_status=f"Analysis failed: {exc!r}"))

    result.summary = _build_summary(info, result.profiles)
    logger.info("Analysis completed.")


# ================================================================ public entry points
def analyze_brave(selected_drive: str, selected_browser: str = "Brave",
                  target_exe_path: Optional[str] = None,
                  log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    """Analyse ONE Brave installation (target_exe_path) and only its profiles.

    If target_exe_path is None, standard locations are searched and the analysis
    proceeds only when exactly ONE installation is found (installations are never merged)."""
    logger = AnalysisLogger(callback=log_callback)
    result = AnalysisResult(drive=selected_drive, started_utc=now_utc_string())
    try:
        if not selected_drive or not selected_browser:
            logger.error("A drive and a browser must both be selected.")
        elif selected_browser.strip().lower() not in SUPPORTED_BROWSER_NAMES:
            logger.error(f"'{selected_browser}' is not supported (only Brave).")
        else:
            exe = target_exe_path
            if not exe:
                found = discover_brave_installations(selected_drive, logger) \
                    if os.path.isdir(selected_drive or "") else []
                if len(found) == 1:
                    exe = found[0]
                    logger.info(f"No executable given; using the only installation found: {exe}")
                elif not found:
                    logger.error("No Brave installation found; pass target_exe_path explicitly.")
                else:
                    logger.error("Several Brave installations found; pass target_exe_path for the "
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


def analyze_all_brave_installations(selected_drive: str,
                                    log_callback: Optional[Callable[[str], None]] = None
                                    ) -> List[AnalysisResult]:
    """One INDEPENDENT AnalysisResult per installation found on the drive."""
    exes = discover_brave_installations(selected_drive) if os.path.isdir(selected_drive or "") else []
    return [analyze_brave(selected_drive, "Brave", exe, log_callback) for exe in exes]


if __name__ == "__main__":
    # python brave_analyzer.py D:\\ "D:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    exe_arg = sys.argv[2] if len(sys.argv) > 2 else None
    outcome = analyze_brave(drive, "Brave", exe_arg, log_callback=print)
    print(json.dumps(outcome.summary, indent=2))
    for row in outcome.websites_visited()[:20]:
        print(row["visit_time"], row["url"])