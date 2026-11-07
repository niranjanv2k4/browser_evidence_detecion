"""
drive_detector.py

Detects the logical drives available on a Windows machine.

- Uses only the standard library (ctypes + the Win32 API), no dependencies.
- Read-only: never writes to any drive.
- Never raises for an individual inaccessible drive; problems are collected
  in DriveInfo.error so the caller can log them instead of silently losing them.

Public API:
    get_available_drives()      -> ["C:\\", "D:\\", ...]
    get_available_drive_info()  -> [DriveInfo, ...]  (type, label, fs, sizes)
"""

import ctypes
import os
import string
import sys
from dataclasses import dataclass
from typing import List, Optional

# Win32 drive type constants (GetDriveTypeW return values)
DRIVE_TYPE_NAMES = {
    0: "Unknown",
    1: "Invalid",
    2: "Removable",
    3: "Fixed",
    4: "Network",
    5: "CD-ROM",
    6: "RAM Disk",
}

# Prevents Windows from showing "No disk in drive" pop-ups for empty readers.
SEM_FAILCRITICALERRORS = 0x0001


@dataclass
class DriveInfo:
    """Information about one logical drive."""
    root: str                          # e.g. "D:\\"
    drive_type: str = "Unknown"        # Fixed, Removable, Network, ...
    label: str = ""                    # Volume label, may be empty
    file_system: str = ""              # NTFS, FAT32, exFAT, ...
    total_bytes: Optional[int] = None  # None = unavailable
    free_bytes: Optional[int] = None   # None = unavailable
    is_ready: bool = False             # True if the volume could be queried
    error: Optional[str] = None        # Reason if it could not be queried

    def display_name(self) -> str:
        """Short text suitable for a GUI radio button."""
        parts = [self.root, f"[{self.drive_type}]"]
        if self.label:
            parts.append(self.label)
        if self.file_system:
            parts.append(self.file_system)
        if self.total_bytes is not None:
            parts.append(f"{self.total_bytes / 1024 ** 3:.1f} GB")
        if not self.is_ready:
            parts.append("(not ready)")
        return " ".join(parts)


def _require_windows() -> None:
    if sys.platform != "win32":
        raise OSError("Drive detection is only supported on Windows.")


def _query_drive(kernel32, root: str, drive_type_id: int) -> DriveInfo:
    """Query one drive. Never raises; failures are stored in .error."""
    info = DriveInfo(root=root,
                     drive_type=DRIVE_TYPE_NAMES.get(drive_type_id, "Unknown"))

    # Volume label + file system
    label_buf = ctypes.create_unicode_buffer(261)
    fs_buf = ctypes.create_unicode_buffer(261)
    ok = kernel32.GetVolumeInformationW(
        root, label_buf, len(label_buf), None, None, None, fs_buf, len(fs_buf)
    )
    if not ok:
        err = ctypes.get_last_error()
        info.error = f"Volume not accessible (Windows error {err}): {ctypes.FormatError(err).strip()}"
        return info

    info.label = label_buf.value
    info.file_system = fs_buf.value
    info.is_ready = True

    # Capacity (optional; failure here does not make the drive unusable)
    free_to_caller = ctypes.c_ulonglong(0)
    total = ctypes.c_ulonglong(0)
    total_free = ctypes.c_ulonglong(0)
    if kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free_to_caller),
                                    ctypes.byref(total), ctypes.byref(total_free)):
        info.total_bytes = total.value
        info.free_bytes = total_free.value
    else:
        err = ctypes.get_last_error()
        info.error = f"Capacity unavailable (Windows error {err})"

    return info


def get_available_drive_info(include_not_ready: bool = False) -> List[DriveInfo]:
    """
    Return detailed info for every logical drive Windows reports.

    include_not_ready: if False (default), drives that cannot be queried
        (empty card reader, disconnected network drive, ...) are left out.
        Set True if you want them returned with is_ready=False and .error set.
    """
    _require_windows()

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetLogicalDrives.restype = ctypes.c_uint32
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint
    kernel32.GetVolumeInformationW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_wchar_p, ctypes.c_uint32,
    ]
    kernel32.GetVolumeInformationW.restype = ctypes.c_int
    kernel32.GetDiskFreeSpaceExW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    kernel32.GetDiskFreeSpaceExW.restype = ctypes.c_int
    kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
    kernel32.SetErrorMode.restype = ctypes.c_uint

    bitmask = kernel32.GetLogicalDrives()  # bit 0 = A:, bit 1 = B:, ...
    drives: List[DriveInfo] = []

    old_mode = kernel32.SetErrorMode(SEM_FAILCRITICALERRORS)
    try:
        for index, letter in enumerate(string.ascii_uppercase):
            if not bitmask & (1 << index):
                continue
            root = f"{letter}:\\"
            drive_type_id = kernel32.GetDriveTypeW(root)
            if drive_type_id in (0, 1):  # unknown / invalid root
                continue
            info = _query_drive(kernel32, root, drive_type_id)
            if info.is_ready or include_not_ready:
                drives.append(info)
    finally:
        kernel32.SetErrorMode(old_mode)

    return drives


def get_available_drives(include_not_ready: bool = False) -> List[str]:
    """
    Return the available drive roots as a simple list, e.g. ["C:\\", "D:\\"].
    An empty list means no usable drives were found.
    """
    return [d.root for d in get_available_drive_info(include_not_ready)]


def is_drive_available(root: str) -> bool:
    """Re-check right before analysis that the selected drive still exists."""
    try:
        return os.path.isdir(root)
    except OSError:
        return False


if __name__ == "__main__":
    try:
        drives = get_available_drive_info(include_not_ready=True)
    except OSError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    if not drives:
        print("No drives detected.")
    else:
        print(f"Found {len(drives)} drive(s):\n")
        for d in drives:
            print(f"  {d.display_name()}")
            if d.error:
                print(f"      note: {d.error}")
        print("\nSimple list:", get_available_drives())