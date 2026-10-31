from detection.drive_detector import get_available_drives
from detection.chrome_detection import get_installed_browsers

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

class BrowserScannerWorker(QThread):
    browser_found = Signal(str, dict)
    finished = Signal()

    def __init__(self, drive):
        super().__init__()
        self.drive = drive

    def run(self):
        browsers = get_installed_browsers(self.drive)
        for browser in browsers:
            self.browser_found.emit(browser["name"], browser)
        self.finished.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Browser Forensic Analyzer")
        self.resize(1200, 750)
        self.setMinimumSize(900, 600)
        self._build_ui()

    def _on_fetch_clicked(self):
        drive = self.source_combo.currentText()
        if not drive or drive == "Select disk image...":
            return

        self.browser_combo.clear()
        self.fetch_button.setText("Fetching...")
        self.fetch_button.setEnabled(False)
        self.source_combo.setEnabled(False)

        self.worker = BrowserScannerWorker(drive)
        self.worker.browser_found.connect(self._on_browser_found)
        self.worker.finished.connect(self._on_fetch_finished)
        self.worker.start()

    def _on_browser_found(self, name, data):
        display_text = f"{name} ({data['version']})"
        self.browser_combo.addItem(display_text, data)

    def _on_fetch_finished(self):
        self.fetch_button.setText("Fetch Browsers")
        self.fetch_button.setEnabled(True)
        self.source_combo.setEnabled(True)
        if self.browser_combo.count() == 0:
            self.browser_combo.addItem("No browsers found")

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(18)

        title = QLabel("Browser Forensic Analyzer")
        title.setObjectName("title")

        subtitle = QLabel("Select an evidence source and browser to begin analysis.")
        subtitle.setObjectName("subtitle")

        main_layout.addWidget(title)
        main_layout.addWidget(subtitle)

        selection_frame = QFrame()
        selection_frame.setObjectName("selectionFrame")

        selection_layout = QVBoxLayout(selection_frame)
        selection_layout.setContentsMargins(20, 18, 20, 18)
        selection_layout.setSpacing(14)

        source_label = QLabel("Select Source")
        source_label.setObjectName("fieldLabel")

        self.source_combo = QComboBox()
        self.source_combo.setCurrentIndex(-1)
        self.source_combo.setPlaceholderText("Select a drive or disk image")

        drives = get_available_drives()
        for drive in drives:
            self.source_combo.addItem(drive)

        self.source_combo.addItem("Select disk image...")

        self.fetch_button = QPushButton("Fetch Browsers")
        self.fetch_button.setObjectName("fetchButton")
        self.fetch_button.setCursor(Qt.PointingHandCursor)
        self.fetch_button.clicked.connect(self._on_fetch_clicked)

        source_row = QHBoxLayout()
        source_row.setSpacing(16)
        source_row.addWidget(source_label)
        source_row.addWidget(self.source_combo, 1)
        source_row.addWidget(self.fetch_button)

        browser_label = QLabel("Select Browser")
        browser_label.setObjectName("fieldLabel")

        self.browser_combo = QComboBox()
        self.browser_combo.setPlaceholderText("Select a detected browser")
        self.browser_combo.setCurrentIndex(-1)

        browser_row = QHBoxLayout()
        browser_row.setSpacing(16)
        browser_row.addWidget(browser_label)
        browser_row.addWidget(self.browser_combo, 1)

        selection_layout.addLayout(source_row)
        selection_layout.addLayout(browser_row)

        self.analyze_button = QPushButton("Analyze")
        self.analyze_button.setObjectName("analyzeButton")
        self.analyze_button.setCursor(Qt.PointingHandCursor)

        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(self.analyze_button)
        button_row.addStretch()

        selection_layout.addLayout(button_row)
        main_layout.addWidget(selection_frame)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        findings_frame = QFrame()
        findings_frame.setObjectName("panel")

        findings_layout = QVBoxLayout(findings_frame)
        findings_layout.setContentsMargins(18, 16, 18, 16)
        findings_layout.setSpacing(10)

        findings_title = QLabel("Findings")
        findings_title.setObjectName("panelTitle")

        self.findings_output = QLabel("Analysis results will appear here.")
        self.findings_output.setObjectName("findingsOutput")
        self.findings_output.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.findings_output.setWordWrap(True)

        findings_layout.addWidget(findings_title)
        findings_layout.addWidget(self.findings_output, 1)

        log_frame = QFrame()
        log_frame.setObjectName("panel")

        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(18, 16, 18, 16)
        log_layout.setSpacing(10)

        log_title = QLabel("Analysis Log")
        log_title.setObjectName("panelTitle")

        self.log_output = QLabel("Analysis activity will appear here.")
        self.log_output.setObjectName("logOutput")
        self.log_output.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.log_output.setWordWrap(True)

        log_layout.addWidget(log_title)
        log_layout.addWidget(self.log_output, 1)

        splitter.addWidget(findings_frame)
        splitter.addWidget(log_frame)
        splitter.setSizes([1, 1])

        main_layout.addWidget(splitter, 1)
        self.statusBar().showMessage("Ready")