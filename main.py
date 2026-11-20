import ctypes
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow
from analysis.extractors.password.brave_pass_extractor import cleanup_brave_extracted_files


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def request_admin_elevation() -> None:
    """
    Relaunches the current script with administrator privileges via Windows UAC prompt.
    """
    if sys.platform != "win32" or is_admin():
        return

    if getattr(sys, "frozen", False):
        exe = sys.executable
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        exe = sys.executable
        params = subprocess.list2cmdline(sys.argv)

    # ShellExecuteW with "runas" triggers the Windows UAC prompt.
    # Returns HINSTANCE > 32 on success.
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    if ret > 32:
        sys.exit(0)
    else:
        sys.exit(1)


def main():
    if not is_admin():
        request_admin_elevation()

    app = QApplication(sys.argv)
    app.aboutToQuit.connect(cleanup_brave_extracted_files)

    stylesheet = Path(__file__).with_name("style.qss")
    if stylesheet.exists():
        app.setStyleSheet(stylesheet.read_text(encoding="utf-8"))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
