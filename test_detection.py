from detection.chrome_detection import find_chrome_registry_entries


entries = find_chrome_registry_entries()

if not entries:
    print("Google Chrome was not found in the registry.")
else:
    for entry in entries:
        print("Chrome found")
        print("Name:", entry["display_name"])
        print("Install location:", entry["install_location"])
        print("Version:", entry["version"])
        print()