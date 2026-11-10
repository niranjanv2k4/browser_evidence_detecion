import os
import re
import sys
import subprocess
import json

# Signer name (lowercase keyword) -> browser name.
# The digital signature is what tells Chrome and Brave apart, and it
# survives renaming the .exe.
VENDORS = {
    "google": "Google Chrome",
    "brave": "Brave Browser",
    "mozilla": "Mozilla Firefox",
}

# Original filenames stored inside the exe's own metadata (not the name on disk).
KNOWN_ORIGINAL_NAMES = {"chrome.exe", "brave.exe", "firefox.exe"}


def check_signature(file_path):
    safe_path = file_path.replace("'", "''")
    ps_cmd = f"(Get-AuthenticodeSignature -LiteralPath '{safe_path}').Status.ToString()"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip() == "Valid"
    except subprocess.CalledProcessError:
        return False


def get_signed_exes(folder):
    """
    One PowerShell call: return every validly signed .exe directly inside
    *folder* as a list of dicts with Path, Size, Original (the original
    filename from the exe's metadata) and Signer (certificate subject).
    """
    safe_folder = folder.replace("'", "''")
    ps_cmd = (
        "ConvertTo-Json -Compress -InputObject @("
        f"Get-ChildItem -LiteralPath '{safe_folder}' -Filter *.exe -File | ForEach-Object {{ "
        "$sig = Get-AuthenticodeSignature -LiteralPath $_.FullName; "
        "if ($sig.Status -eq 'Valid') { "
        "[pscustomobject]@{ Path = $_.FullName; Size = $_.Length; "
        "Original = $_.VersionInfo.OriginalFilename; "
        "Signer = $sig.SignerCertificate.Subject } } }"
        ")"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            check=True
        )
        data = json.loads(result.stdout.strip() or "[]")
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return []
    return [data] if isinstance(data, dict) else data


def pick_main_exe(exes, vendor_keyword):
    """
    From the signed exes in a folder, return the main browser executable
    for the given vendor, whatever it has been renamed to.

    Helper exes (chrome_proxy.exe, updater.exe, ...) share the same signer,
    so prefer the one whose original filename is a known browser name,
    and fall back to the largest file.
    """
    candidates = [
        e for e in exes
        if vendor_keyword in (e.get("Signer") or "").lower()
    ]
    if not candidates:
        return None

    named = [
        e for e in candidates
        if (e.get("Original") or "").lower() in KNOWN_ORIGINAL_NAMES
    ]
    return max(named or candidates, key=lambda e: e["Size"])


def find_chromium_version(root, dirs, version_pattern):
    """
    Return the version folder name if *root* has the structure of a
    Chromium-based browser (Chrome / Brave), otherwise None.
    """
    for directory in dirs:
        if not version_pattern.match(directory):
            continue

        version_path = os.path.join(root, directory)

        dll_path = os.path.join(version_path, 'chrome.dll')
        if not os.path.exists(dll_path):
            dll_path = os.path.join(version_path, 'brave.dll')

        if not (os.path.exists(dll_path) and check_signature(dll_path)):
            continue
            
        elf_path = os.path.join(version_path, 'chrome_elf.dll')
        if not os.path.exists(elf_path):
            elf_path = os.path.join(version_path, 'brave_elf.dll')

        icu_path = os.path.join(version_path, 'icudtl.dat')
        v8_path = os.path.join(version_path, 'v8_context_snapshot.bin')
        locales_path = os.path.join(version_path, 'Locales')

        if (os.path.exists(elf_path) and
            os.path.exists(icu_path) and
            os.path.exists(v8_path) and
            os.path.isdir(locales_path)):
            return directory

    return None


def get_installed_browsers(search_path):
    version_pattern = re.compile(r'^\d+\.\d+\.\d+(\.\d+)?$')

    for root, dirs, files in os.walk(search_path):
        # Nothing to do in folders that contain no executables
        if not any(f.lower().endswith('.exe') for f in files):
            continue

        # --- Check for Chromium-based browsers (Chrome / Brave) ---
        version = find_chromium_version(root, dirs, version_pattern)
        if version:
            exes = get_signed_exes(root)
            for keyword in ("google", "brave"):
                main_exe = pick_main_exe(exes, keyword)
                if main_exe:
                    yield {
                        "name": VENDORS[keyword],
                        "path": str(main_exe["Path"]),
                        "version": version,
                    }
                    break

        # --- Check for Firefox ---
        xul_path = os.path.join(root, 'xul.dll')
        mozglue_path = os.path.join(root, 'mozglue.dll')
        omni_path = os.path.join(root, 'omni.ja')
        app_ini_path = os.path.join(root, 'application.ini')

        if (os.path.exists(xul_path) and check_signature(xul_path) and
            os.path.exists(mozglue_path) and
            os.path.exists(omni_path) and
            os.path.exists(app_ini_path)):

            main_exe = pick_main_exe(get_signed_exes(root), "mozilla")
            if main_exe:
                firefox_version = "Unknown"
                try:
                    with open(app_ini_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.startswith('Version='):
                                firefox_version = line.split('=')[1].strip()
                                break
                except Exception:
                    pass

                yield {
                    "name": VENDORS["mozilla"],
                    "path": str(main_exe["Path"]),
                    "version": firefox_version,
                }


if __name__ == "__main__":
    target_drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    print(f"Scanning {target_drive} for browsers ...\n")

    for installed in get_installed_browsers(target_drive):
        print(json.dumps(installed, indent=2))