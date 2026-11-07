"""
Brave Detector — scans a given Windows drive for installed Brave Browser
and returns structured information about each installation.

Public API
----------
    get_installed_braves(drive)  → list[dict]   # primary — used by the UI
    get_brave_summary(drive)     → list[str]    # convenience wrapper
"""

import ctypes
import ctypes.wintypes as wintypes
import struct
from pathlib import Path


# ═══════════════════════════════════════════════════════════════════════════
# Windows Version-Info API  (ctypes — no external dependencies)
# ═══════════════════════════════════════════════════════════════════════════

_ver = ctypes.windll.version

_ver.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, wintypes.LPDWORD]
_ver.GetFileVersionInfoSizeW.restype  = wintypes.DWORD

_ver.GetFileVersionInfoW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
]
_ver.GetFileVersionInfoW.restype = wintypes.BOOL

_ver.VerQueryValueW.argtypes = [
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.UINT),
]
_ver.VerQueryValueW.restype = wintypes.BOOL


def _read_version_info(exe_path: str) -> dict[str, str] | None:
    """
    Read the version-resource metadata embedded in a Windows PE file.

    Returns a dict with keys such as ``CompanyName``, ``FileDescription``,
    ``ProductVersion``, etc.  Returns ``None`` when the resource cannot
    be read (file missing, not a PE, or no version resource).
    """
    size = _ver.GetFileVersionInfoSizeW(exe_path, None)
    if not size:
        return None

    buf = ctypes.create_string_buffer(size)
    if not _ver.GetFileVersionInfoW(exe_path, 0, size, buf):
        return None

    lp = ctypes.c_void_p()
    cb = wintypes.UINT()
    if not _ver.VerQueryValueW(
        buf, r"\VarFileInfo\Translation",
        ctypes.byref(lp), ctypes.byref(cb),
    ):
        return None
    if cb.value < 4:
        return None

    lang, cp = struct.unpack_from(
        "<HH", (ctypes.c_char * 4).from_address(lp.value),
    )
    prefix = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\"

    _FIELDS = (
        "CompanyName",
        "FileDescription",
        "ProductName",
        "ProductVersion",
        "FileVersion",
        "OriginalFilename",
    )

    info: dict[str, str] = {}
    for field in _FIELDS:
        val_p = ctypes.c_void_p()
        val_len = wintypes.UINT()
        if _ver.VerQueryValueW(
            buf, prefix + field,
            ctypes.byref(val_p), ctypes.byref(val_len),
        ) and val_p.value and val_len.value:
            info[field] = ctypes.wstring_at(val_p.value)

    return info or None


# ═══════════════════════════════════════════════════════════════════════════
# Identity verification
# ═══════════════════════════════════════════════════════════════════════════

def _is_brave_browser(info: dict[str, str]) -> bool:
    """
    Return ``True`` only when the PE metadata positively identifies
    the executable as Brave Browser.
    """
    company = info.get("CompanyName", "").lower()
    product = info.get("ProductName", "").lower()
    return "brave" in company and "brave" in product


# ═══════════════════════════════════════════════════════════════════════════
# Candidate-location builder
# ═══════════════════════════════════════════════════════════════════════════

_BRAVE_REL = Path("BraveSoftware") / "Brave-Browser" / "Application"


def _candidate_locations(drive_root: Path) -> list[dict]:
    """
    Return candidate Brave *Application* directories on *drive_root*.

    Each entry is ``{"app_dir": Path, "install_type": str}``.

    To support non-standard install locations in the future, append
    additional entries to the list returned here.
    """
    candidates: list[dict] = [
        # 64-bit system-wide installation
        {
            "app_dir": drive_root / "Program Files" / _BRAVE_REL,
            "install_type": "system",
        },
        # 32-bit installation on 64-bit Windows
        {
            "app_dir": drive_root / "Program Files (x86)" / _BRAVE_REL,
            "install_type": "system_x86",
        },
    ]

    # Per-user installations
    users_dir = drive_root / "Users"
    if users_dir.is_dir():
        try:
            for entry in users_dir.iterdir():
                if not entry.is_dir():
                    continue
                candidates.append({
                    "app_dir": entry / "AppData" / "Local" / _BRAVE_REL,
                    "install_type": f"user ({entry.name})",
                })
        except OSError:
            pass

    return candidates


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════

def get_installed_braves(drive: str) -> list[dict]:
    """
    Scan *drive* for installed Brave browsers.

    Parameters
    ----------
    drive : str
        Drive root — ``"C"``, ``"C:"``, ``"C:\\\\"``, etc.

    Returns
    -------
    list[dict]
        One dict per installation::

            {
                "path":         str,  # absolute path to brave.exe
                "version":      str,  # e.g. "1.73.104"
                "install_type": str,  # "system" | "system_x86" | "user (<name>)"
            }

        Empty list when no installation is found.
    """
    drive = drive.strip().rstrip(":\\/")
    drive_root = Path(f"{drive}:\\")

    if not drive_root.exists():
        return []

    results: list[dict] = []

    for candidate in _candidate_locations(drive_root):
        brave_exe = candidate["app_dir"] / "brave.exe"

        # ── file exists? ─────────────────────────────────────────────
        try:
            if not brave_exe.is_file():
                continue
        except OSError:
            continue

        # ── read PE metadata ─────────────────────────────────────────
        info = _read_version_info(str(brave_exe))
        if info is None:
            continue

        # ── verify this is actually Brave Browser ────────────────────
        if not _is_brave_browser(info):
            continue

        # ── version from the executable's own metadata ───────────────
        version = (
            info.get("ProductVersion")
            or info.get("FileVersion")
            or "unknown"
        )

        results.append({
            "path": str(brave_exe),
            "version": version,
            "install_type": candidate["install_type"],
        })

    return results


def get_brave_summary(drive: str) -> list[str]:
    """
    Convenience helper — return the version strings of every Brave
    installation found on *drive*, sorted newest-first.
    """
    versions = [b["version"] for b in get_installed_braves(drive)]
    try:
        versions.sort(
            key=lambda v: tuple(int(p) for p in v.split(".")),
            reverse=True,
        )
    except (ValueError, AttributeError):
        versions.sort(reverse=True)
    return versions


# ═══════════════════════════════════════════════════════════════════════════
# Quick self-test  (python brave_detector.py)
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import json

    test_drive = "C"
    print(f"Scanning {test_drive}:\\ for Brave installations …\n")

    installed = get_installed_braves(test_drive)
    if installed:
        print(json.dumps(installed, indent=2))
    else:
        print("No Brave installations found.")

    print(f"\nSummary: {get_brave_summary(test_drive)}")
