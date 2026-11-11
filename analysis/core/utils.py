import configparser
import ctypes
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .constants import CHROME_EPOCH, SKIPPED_USER_DIRS, UNIX_EPOCH

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

def firefox_time_to_string(value: Any) -> Optional[str]:
    try:
        number = int(value)
        if number <= 0:
            return None
        return format_utc(UNIX_EPOCH + timedelta(microseconds=number))
    except (TypeError, ValueError, OverflowError):
        return None

def _firefox_seconds_to_string(value: Any) -> Optional[str]:
    try:
        number = int(value)
        if number <= 0:
            return None
        return format_utc(UNIX_EPOCH + timedelta(seconds=number))
    except (TypeError, ValueError, OverflowError):
        return None

def _ms_epoch_to_string(value: Any) -> Optional[str]:
    try:
        number = int(value)
        if number <= 0:
            return None
        return format_utc(UNIX_EPOCH + timedelta(milliseconds=number))
    except (TypeError, ValueError, OverflowError):
        return None

def now_utc_string() -> str:
    return format_utc(datetime.now(timezone.utc))

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
    parser.optionxform = str
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

def list_windows_users(root_drive: str, logger: Any) -> List[str]:
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