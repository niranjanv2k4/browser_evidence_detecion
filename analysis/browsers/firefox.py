import os
import re
import string
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from analysis.core.constants import FIREFOX_SPEC, PROFILE_MARKERS
from analysis.core.logger import AnalysisLogger
from analysis.core.models import AnalysisResult, BrowserInfo, ProfileResult
from analysis.core.utils import (
    get_domain, list_windows_users, now_utc_string, read_ini
)
from analysis.extractors.firefox_extractor import (
    DatabaseAccessError, _count_extensions, _read_firefox_cookies,
    _read_places, _with_database
)

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

def discover_firefox_installations(root_drive: str,
                                   logger: Optional[AnalysisLogger] = None) -> List[str]:
    logger = logger or AnalysisLogger()
    found: List[str] = []
    for relative in FIREFOX_SPEC.system_install_dirs:
        candidate = os.path.normpath(os.path.join(root_drive, relative, FIREFOX_SPEC.exe_name))
        if os.path.isfile(candidate):
            found.append(candidate)
    for user in list_windows_users(root_drive, logger):
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

_ABS_WIN = re.compile(r"^[A-Za-z]:[\\/]")

def _norm_key(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))

def _resolve_profile_path(raw: str, is_relative: Optional[bool], firefox_root: str,
                          root_drive: str) -> str:
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
    m = re.fullmatch(r"[a-z0-9]{8}\.(.+)", directory_name)
    return m.group(1) if m else directory_name

def _parse_profiles_ini(firefox_root: str, root_drive: str, logger: AnalysisLogger,
                        user: str) -> Tuple[List[Dict], Dict[str, Dict]]:
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
    specs: Dict[str, Dict] = {}
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
    hash_lookup: Dict[str, Tuple[str, str]] = {}
    for letter, digest in info.install_hash_candidates.items():
        kind = "exact" if letter == exact_letter else "drive-letter substituted"
        if digest not in hash_lookup or kind == "exact":
            hash_lookup[digest] = (letter, kind)

    for user in list_windows_users(root_drive, logger):
        firefox_root = os.path.normpath(os.path.join(root_drive, "Users", user,
                                                     FIREFOX_SPEC.per_user_data_dir))
        if not os.path.isdir(firefox_root):
            continue
        logger.info(f"Firefox data root found for user '{user}': {firefox_root}")
        if firefox_root not in info.user_data_paths:
            info.user_data_paths.append(firefox_root)

        entries, installs = _parse_profiles_ini(firefox_root, root_drive, logger, user)
        by_key = {_norm_key(e["path"]): e for e in entries}

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
    else:
        try:
            data, method, digest = _with_database(places_path, logger, lambda c: _read_places(c, name, logger))
            profile.visits = data["visits"]
            profile.history_db_sha256 = digest
            profile.visit_count = sum(v.visit_count for v in profile.visits)
            profile.unique_url_count = len({v.url for v in profile.visits})
            profile.unique_domain_count = len({get_domain(v.url) for v in profile.visits} - {None})
            profile.bookmark_count = data["bookmarks"]
            profile.download_count = data["downloads"]
            profile.downloads = data["download_records"]
            profile.history_status = (f"Read OK ({method})" if profile.visits
                                      else f"Read OK, no records ({method})")
            logger.info(f"{name}: {profile.visit_count:,} visits, {profile.unique_url_count:,} unique URLs, "
                        f"{profile.unique_domain_count:,} unique domains.")
        except DatabaseAccessError as exc:
            profile.history_status = f"Unavailable: {exc}"
            logger.warning(f"places.sqlite unavailable for {name}: {exc}")

    cookies_path = os.path.join(spec["path"], "cookies.sqlite")
    if os.path.isfile(cookies_path):
        try:
            c_data, c_method, c_digest = _with_database(cookies_path, logger, lambda c: _read_firefox_cookies(c, name))
            profile.cookies = c_data
            profile.cookie_count = len(c_data)
            logger.info(f"{name}: {profile.cookie_count:,} cookies found.")
        except DatabaseAccessError as exc:
            logger.warning(f"cookies.sqlite unavailable for {name}: {exc}")

    return profile

def _build_summary(info: BrowserInfo, profiles: List[ProfileResult],
                   unattributed: List[ProfileResult]) -> Dict:
    visits = [v for p in profiles for v in p.visits]
    firsts = [v.first_visit_time for v in visits if v.first_visit_time]
    lasts = [v.visit_time for v in visits if v.visit_time]
    return {
        "executable_path": info.executable_path,
        "version": info.version,
        "profile_count": len(profiles),
        "profile_names": [p.profile_name for p in profiles],
        "profiles_with_history": sum(1 for p in profiles if p.history_status.startswith("Read OK")),
        "windows_users": sorted({p.windows_user for p in profiles}),
        "unattributed_profile_count": len(unattributed),
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
    for spec in other:
        result.unattributed_profiles.append(ProfileResult(
            directory_name=spec["directory_name"], path=spec["path"], windows_user=spec["windows_user"],
            profile_name=spec["profile_name"], attribution="unattributed",
            attribution_basis=spec["attribution_basis"],
            history_status="Not analyzed (not tied to this installation)"))

    result.summary = _build_summary(info, result.profiles, result.unattributed_profiles)
    logger.info("Analysis completed.")

def analyze_firefox(selected_drive: str, selected_browser: str = "Mozilla Firefox",
                    target_exe_path: Optional[str] = None,
                    log_callback: Optional[Callable[[str], None]] = None) -> AnalysisResult:
    SUPPORTED_BROWSER_NAMES = {
        "mozilla firefox", "firefox", "firefox esr", "firefox developer edition",
        "firefox nightly", "firefox beta", "mozilla firefox esr"
    }
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
    exes = discover_firefox_installations(selected_drive) if os.path.isdir(selected_drive or "") else []
    return [analyze_firefox(selected_drive, "Mozilla Firefox", exe, log_callback) for exe in exes]