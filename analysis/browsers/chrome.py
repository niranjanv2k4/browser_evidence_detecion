import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from analysis.core.constants import CHROME_SPEC, PROFILE_DIR_PATTERN
from analysis.core.logger import AnalysisLogger
from analysis.core.models import (
    AnalysisResult, BrowserInfo, BrowserLocation,
    HistoryStatistics, ProfileResult, VisitRecord
)
from analysis.core.utils import (
    chrome_time_to_string, dig, format_utc, get_domain,
    get_file_version, list_windows_users, now_utc_string,
    read_json_file, file_metadata
)
from analysis.extractors.chromium_extractor import (
    HistoryAccessError, _read_cookies, _read_history, _with_history
)

def locate_browser(root_drive: str, spec: Any, logger: AnalysisLogger) -> Optional[BrowserLocation]:
    executables: List[str] = []
    user_data_dirs: List[Dict[str, str]] = []

    for relative in spec.system_install_dirs:
        candidate = os.path.normpath(os.path.join(root_drive, relative, spec.exe_name))
        if os.path.isfile(candidate):
            executables.append(candidate)

    for user in list_windows_users(root_drive, logger):
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

def _locate_specific_browser(root_drive: str, exe_path: str, spec: Any, logger: AnalysisLogger) -> BrowserLocation:
    executables = [exe_path] if os.path.isfile(exe_path) else []
    user_data_dirs = []

    exe_dir = os.path.dirname(exe_path)
    adjacent_data = os.path.join(exe_dir, "User Data")
    
    if os.path.isdir(adjacent_data):
        user_data_dirs.append({"windows_user": "portable/adjacent", "path": adjacent_data})
        logger.info(f"Adjacent User Data directory found at {adjacent_data}")

    for user in list_windows_users(root_drive, logger):
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
        info.notes.append("Executable not found; browser may be uninstalled or in a non-standard location.")
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

def _discover_profiles(windows_user: str, user_data_path: str, logger: AnalysisLogger) -> List[Dict]:
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
            continue
        if not (os.path.isfile(os.path.join(path, "Preferences")) or os.path.isfile(os.path.join(path, "History"))):
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

    profile.profile_name = profile.display_name or profile.directory_name
    
def compute_statistics(records: List[VisitRecord]) -> HistoryStatistics:
    times = [r.visit_time for r in records if r.visit_time]
    domains = {get_domain(r.url) for r in records} - {None}
    return HistoryStatistics(
        history_record_count=len(records),
        total_visits=sum(r.visit_count for r in records),
        unique_url_count=len({r.url for r in records}),
        unique_domain_count=len(domains),
        first_visit=min(times) if times else None,
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
        logger.warning(f"History database not found for {name}.")
    else:
        profile.history_db_path = history_path
        logger.info("History database found. Reading history...")
        try:
            data, method, digest = _with_history(history_path, logger, lambda c: _read_history(c, name, logger))
            profile.visits = data["visits"]
            profile.downloads = data["download_records"]
            profile.history_db_sha256 = digest
            profile.statistics = compute_statistics(profile.visits)
            if profile.visits:
                profile.history_status = f"Read OK ({method})"
                logger.info(f"{name}: {len(profile.visits):,} history records, "
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
            c_records, c_method, c_sha256 = _with_history(cookies_path, logger, lambda c: _read_cookies(c, name))
            profile.cookies = c_records
            profile.cookie_count = len(c_records)
            logger.info(f"{name}: {profile.cookie_count:,} cookies found.")
        except HistoryAccessError as exc:
            logger.warning(f"Cookies database unavailable for {name}: {exc}")

    return profile

def _build_summary(profiles: List[ProfileResult]) -> Dict:
    all_records = [r for p in profiles for r in p.visits]
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
        "download_count": sum(len(p.downloads) for p in profiles),
        "cookie_count": sum(p.cookie_count for p in profiles),
    }

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

def analyze_chrome(selected_drive: str, selected_browser: str = "Google Chrome",
                   target_exe_path: Optional[str] = None,
                   log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    logger = AnalysisLogger(callback=log_callback)
    result = AnalysisResult(drive=selected_drive, started_utc=now_utc_string())
    try:
        SUPPORTED_BROWSER_NAMES = {"google chrome", "chrome"}
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