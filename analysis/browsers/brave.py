import os
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from analysis.core.constants import (
    BRAVE_CHANNELS, BRAVE_EXE_NAME, BRAVE_VENDOR_DIR, PROFILE_DIR_PATTERN
)
from analysis.core.logger import AnalysisLogger
from analysis.core.models import AnalysisResult, BrowserInfo, ProfileResult
from analysis.core.utils import (
    dig, get_domain, list_windows_users, now_utc_string, read_json_file
)
from analysis.extractors.chromium_extractor import (
    HistoryAccessError, _read_cookies, _read_history, _with_history
)

def discover_brave_installations(root_drive: str, logger: Optional[AnalysisLogger] = None) -> List[str]:
    logger = logger or AnalysisLogger()
    found: List[str] = []
    for program_dir in ("Program Files", "Program Files (x86)"):
        for channel in BRAVE_CHANNELS:
            candidate = os.path.normpath(os.path.join(
                root_drive, program_dir, BRAVE_VENDOR_DIR, channel, "Application", BRAVE_EXE_NAME))
            if os.path.isfile(candidate):
                found.append(candidate)
    for user in list_windows_users(root_drive, logger):
        for channel in BRAVE_CHANNELS:
            candidate = os.path.normpath(os.path.join(
                root_drive, "Users", user, "AppData", "Local", BRAVE_VENDOR_DIR, channel,
                "Application", BRAVE_EXE_NAME))
            if os.path.isfile(candidate):
                found.append(candidate)
    return found

def _detect_channel(exe_path: str) -> Optional[str]:
    for part in reversed(Path(exe_path.replace("\\", "/")).parts):
        for channel in BRAVE_CHANNELS:
            if part.lower() == channel.lower():
                return channel
    return None

def _install_owner(exe_path: str, root_drive: str) -> Optional[str]:
    try:
        parts = Path(os.path.relpath(exe_path, root_drive)).parts
    except ValueError:
        return None
    if len(parts) > 2 and parts[0].lower() == "users":
        return parts[1]
    return None

def _version_from_folder(application_dir: str) -> Optional[str]:
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
    if os.path.basename(exe_path).lower() != BRAVE_EXE_NAME:
        logger.warning(f"Executable is not named {BRAVE_EXE_NAME}; analysing anyway.")
    info.version = _version_from_folder(info.installation_path or "")
    if info.version:
        logger.info(f"Brave version: {info.version}")
    return info

def _profile_sort_key(name: str) -> Tuple[int, int, str]:
    if name.lower() == "default":
        return (0, 0, name)
    m = re.fullmatch(r"Profile (\d+)", name, re.IGNORECASE)
    return (1, int(m.group(1)), name) if m else (2, 0, name)

def _discover_profiles(windows_user: str, user_data_path: str, basis: str,
                       logger: AnalysisLogger) -> List[Dict]:
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
            continue
        if not (os.path.isfile(os.path.join(path, "Preferences")) or os.path.isfile(os.path.join(path, "History"))):
            continue
        cache = info_cache.get(name)
        profiles.append({"directory_name": name, "path": path, "windows_user": windows_user,
                         "cache_name": cache.get("name") if isinstance(cache, dict) else None,
                         "basis": basis})
    return profiles

def _locate_user_data(root_drive: str, exe_path: str, info: BrowserInfo,
                      logger: AnalysisLogger) -> List[Tuple[str, str, str]]:
    exe_dir = os.path.dirname(exe_path)
    candidates = [os.path.join(exe_dir, "User Data")]
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
        users = list_windows_users(root_drive, logger)

    found = []
    for user in users:
        data_dir = os.path.normpath(os.path.join(root_drive, "Users", user, "AppData", "Local",
                                                 BRAVE_VENDOR_DIR, channel, "User Data"))
        if os.path.isdir(data_dir):
            found.append((user, data_dir, f"{channel} User Data of user '{user}' "
                                          f"({info.install_scope} install)"))

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
    prefs, error = read_json_file(os.path.join(profile_path, "Preferences"))
    if error:
        logger.warning(f"Preferences unavailable for {profile}: {error}")
        return None, 0
    settings = dig(prefs, "extensions", "settings")
    count = sum(1 for value in settings.values() if isinstance(value, dict)) if isinstance(settings, dict) else 0
    return dig(prefs, "profile", "name") or None, count

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
    else:
        try:
            data, method, digest = _with_history(history_path, logger, lambda c: _read_history(c, directory, logger))
            profile.visits = data["visits"]
            profile.history_db_sha256 = digest
            profile.download_count = data["downloads"]
            profile.downloads = data["download_records"]
            profile.visit_count = sum(v.visit_count for v in profile.visits)
            profile.unique_url_count = len({v.url for v in profile.visits})
            profile.unique_domain_count = len({get_domain(v.url) for v in profile.visits} - {None})
            profile.history_status = f"Read OK ({method})" if profile.visits else f"Read OK, no records ({method})"
            logger.info(f"{directory}: {profile.visit_count:,} visits, {profile.unique_url_count:,} unique URLs, "
                        f"{profile.unique_domain_count:,} unique domains.")
        except HistoryAccessError as exc:
            profile.history_status = f"Unavailable: {exc}"
            logger.warning(f"History database unavailable for {directory}: {exc}")

    cookies_paths = [os.path.join(spec["path"], "Network", "Cookies"), os.path.join(spec["path"], "Cookies")]
    cookies_path = next((p for p in cookies_paths if os.path.isfile(p)), None)
    if cookies_path:
        try:
            c_data, c_method, c_digest = _with_history(cookies_path, logger, lambda c: _read_cookies(c, directory))
            profile.cookies = c_data
            profile.cookie_count = len(c_data)
            logger.info(f"{directory}: {profile.cookie_count:,} cookies found.")
        except HistoryAccessError as exc:
            logger.warning(f"Cookies database unavailable for {directory}: {exc}")

    return profile

def _build_summary(info: BrowserInfo, profiles: List[ProfileResult]) -> Dict:
    visits = [v for p in profiles for v in p.visits]
    firsts = [v.first_visit_time for v in visits if v.first_visit_time]
    lasts = [v.visit_time for v in visits if v.visit_time]
    return {
        "executable_path": info.executable_path,
        "version": info.version,
        "channel": info.channel,
        "install_scope": info.install_scope,
        "profile_count": len(profiles),
        "profile_names": [p.profile_name for p in profiles],
        "profiles_with_history": sum(1 for p in profiles if p.history_status.startswith("Read OK")),
        "windows_users": sorted({p.windows_user for p in profiles}),
        "history_record_count": len(visits),
        "unique_url_count": len({v.url for v in visits}),
        "unique_domain_count": len({get_domain(v.url) for v in visits} - {None}),
        "bookmark_count": sum(p.bookmark_count for p in profiles),
        "download_count": sum(p.download_count for p in profiles),
        "extension_count": sum(p.extension_count for p in profiles),
        "cookie_count": sum(p.cookie_count for p in profiles),
        "total_visits": sum(v.visit_count for v in visits),
        "first_visit": min(firsts) if firsts else (min(lasts) if lasts else None),
        "last_visit": max(lasts) if lasts else None,
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

def analyze_brave(selected_drive: str, selected_browser: str = "Brave",
                  target_exe_path: Optional[str] = None,
                  log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    SUPPORTED_BROWSER_NAMES = {
        "brave", "brave browser", "brave-browser", "brave beta", "brave nightly",
        "brave dev", "brave-browser-beta", "brave-browser-nightly", "brave-browser-dev"
    }
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
    exes = discover_brave_installations(selected_drive) if os.path.isdir(selected_drive or "") else []
    return [analyze_brave(selected_drive, "Brave", exe, log_callback) for exe in exes]