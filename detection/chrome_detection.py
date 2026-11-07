import os
import re
import sys
import subprocess
import json

def check_signature(file_path):
    ps_cmd = f"(Get-AuthenticodeSignature -LiteralPath '{file_path}').Status.ToString()"
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

def get_installed_browsers(search_path):
    version_pattern = re.compile(r'^\d+\.\d+\.\d+(\.\d+)?$')

    for root, dirs, files in os.walk(search_path):
        # --- Check for Google Chrome ---
        if 'chrome.exe' in files:
            exe_path = os.path.join(root, 'chrome.exe')
            
            if check_signature(exe_path):
                for directory in dirs:
                    if version_pattern.match(directory):
                        version_path = os.path.join(root, directory)
                        dll_path = os.path.join(version_path, 'chrome.dll')
                        
                        if os.path.exists(dll_path) and check_signature(dll_path):
                            elf_path = os.path.join(version_path, 'chrome_elf.dll')
                            icu_path = os.path.join(version_path, 'icudtl.dat')
                            v8_path = os.path.join(version_path, 'v8_context_snapshot.bin')
                            locales_path = os.path.join(version_path, 'Locales')
                            
                            if (os.path.exists(elf_path) and 
                                os.path.exists(icu_path) and 
                                os.path.exists(v8_path) and 
                                os.path.isdir(locales_path)):
                                
                                yield {
                                    "name": "Google Chrome",
                                    "path": str(exe_path),
                                    "version": directory,
                                }
                                break

        # --- Check for Brave Browser ---
        if 'brave.exe' in files:
            exe_path = os.path.join(root, 'brave.exe')
            
            if check_signature(exe_path):
                for directory in dirs:
                    if version_pattern.match(directory):
                        version_path = os.path.join(root, directory)
                        
                        dll_path = os.path.join(version_path, 'brave.dll')
                        if not os.path.exists(dll_path):
                            dll_path = os.path.join(version_path, 'chrome.dll')
                        
                        if os.path.exists(dll_path) and check_signature(dll_path):
                            elf_path = os.path.join(version_path, 'brave_elf.dll')
                            if not os.path.exists(elf_path):
                                elf_path = os.path.join(version_path, 'chrome_elf.dll')
                                
                            icu_path = os.path.join(version_path, 'icudtl.dat')
                            v8_path = os.path.join(version_path, 'v8_context_snapshot.bin')
                            locales_path = os.path.join(version_path, 'Locales')
                            
                            if (os.path.exists(elf_path) and 
                                os.path.exists(icu_path) and 
                                os.path.exists(v8_path) and 
                                os.path.isdir(locales_path)):
                                
                                yield {
                                    "name": "Brave Browser",
                                    "path": str(exe_path),
                                    "version": directory,
                                }
                                break

        if 'firefox.exe' in files:
            exe_path = os.path.join(root, 'firefox.exe')
            
            if check_signature(exe_path):
                xul_path = os.path.join(root, 'xul.dll')
                mozglue_path = os.path.join(root, 'mozglue.dll')
                omni_path = os.path.join(root, 'omni.ja')
                app_ini_path = os.path.join(root, 'application.ini')
                
                if (os.path.exists(xul_path) and check_signature(xul_path) and
                    os.path.exists(mozglue_path) and 
                    os.path.exists(omni_path) and 
                    os.path.exists(app_ini_path)):
                    
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
                        "name": "Mozilla Firefox",
                        "path": str(exe_path),
                        "version": firefox_version,
                    }


    

if __name__ == "__main__":
    target_drive = sys.argv[1] if len(sys.argv) > 1 else "C:\\"
    print(f"Scanning {target_drive} for browsers ...\n")
    
    for installed in get_installed_browsers(target_drive):
        print(json.dumps(installed, indent=2))