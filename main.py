import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow
from analysis.extractors.password.brave_pass_extractor import cleanup_brave_extracted_files


def main():
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
