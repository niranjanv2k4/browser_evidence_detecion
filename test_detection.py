from detection.browser_detection import BrowserDetector


detector = BrowserDetector()

browsers = detector.detect()

for name, information in browsers.items():
    print(f"Browser: {name}")
    print(f"Version: {information['version']}")
    print(f"Location: {information['install_location']}")
    print()