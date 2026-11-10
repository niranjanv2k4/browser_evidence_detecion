# ui/main_window.py
import json
from dataclasses import asdict
from detection.drive_detector import get_available_drives
from detection.chrome_detection import get_installed_browsers
from analysis.chrome_analyzer import analyze_chrome
from analysis.firefox_analyzer import analyze_firefox
from analysis.brave_analyzer import analyze_brave
from ui.websites_window import WebsitesWindow
from ui.downloads_window import DownloadsWindow
from ui.cookies_window import CookiesWindow
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
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
        self._is_running = True

    def run(self):
        browsers = get_installed_browsers(self.drive)
        for browser in browsers:
            if not self._is_running:
                break
            self.browser_found.emit(browser["name"], browser)
        self.finished.emit()

    def stop(self):
        self._is_running = False


class AnalyzerWorker(QThread):
    log_emitted = Signal(str)
    finished = Signal(object)

    def __init__(self, drive, browser_name, exe_path):
        super().__init__()
        self.drive = drive
        self.browser_name = browser_name
        self.exe_path = exe_path

    def run(self):
        browser_lower = self.browser_name.lower()
        
        if "firefox" in browser_lower:
            result = analyze_firefox(
                selected_drive=self.drive,
                selected_browser=self.browser_name,
                target_exe_path=self.exe_path,
                log_callback=lambda msg: self.log_emitted.emit(msg)
            )
        elif "brave" in browser_lower:
            result = analyze_brave(
                selected_drive=self.drive,
                selected_browser=self.browser_name,
                target_exe_path=self.exe_path,
                log_callback=lambda msg: self.log_emitted.emit(msg)
            )
        else:
            result = analyze_chrome(
                selected_drive=self.drive,
                selected_browser=self.browser_name,
                target_exe_path=self.exe_path,
                log_callback=lambda msg: self.log_emitted.emit(msg)
            )
            
        self.finished.emit(result)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Browser Forensic Analyzer")
        self.resize(1200, 750)
        self.setMinimumSize(900, 600)
        self.current_profiles_data = {}
        self.current_downloads_data = {}
        self.current_cookies_data = {}
        self._build_ui()

    def _on_fetch_clicked(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.stop()
            self.fetch_button.setText("Stopping...")
            self.fetch_button.setEnabled(False)
            return

        drive = self.source_combo.currentText()
        if not drive or drive == "Select disk image...":
            return

        self.browser_combo.clear()
        self.fetch_button.setText("Stop Fetching")
        self.source_combo.setEnabled(False)

        self.worker = BrowserScannerWorker(drive)
        self.worker.browser_found.connect(self._on_browser_found)
        self.worker.finished.connect(self._on_fetch_finished)
        self.worker.start()

    def _on_browser_found(self, name, data):
        display_text = f"{name} ({data['version']}) - {data['path']}"
        self.browser_combo.addItem(display_text, data)

    def _on_fetch_finished(self):
        self.fetch_button.setText("Fetch Browsers")
        self.fetch_button.setEnabled(True)
        self.source_combo.setEnabled(True)
        if self.browser_combo.count() == 0:
            self.browser_combo.addItem("No browsers found")

    def _on_analyze_clicked(self):
        drive = self.source_combo.currentText()
        browser_data = self.browser_combo.currentData()
        
        if not browser_data:
            return
            
        browser_name = browser_data["name"]
        exe_path = browser_data["path"]

        self.analyze_button.setText("Analyzing...")
        self.analyze_button.setEnabled(False)
        self.websites_button.setEnabled(False)
        self.downloads_button.setEnabled(False)
        self.cookies_button.setEnabled(False)
        self.current_profiles_data = {}
        self.current_downloads_data = {}
        self.current_cookies_data = {}
        
        self.log_output.clear()
        self.findings_output.setPlainText("Analysis in progress...")
        
        self.analyzer_worker = AnalyzerWorker(drive, browser_name, exe_path)
        self.analyzer_worker.log_emitted.connect(self._on_log_emitted)
        self.analyzer_worker.finished.connect(self._on_analysis_finished)
        self.analyzer_worker.start()

    def _on_log_emitted(self, msg):
        self.log_output.appendPlainText(msg)

    def _on_analysis_finished(self, result):
        self.analyze_button.setText("Analyze")
        self.analyze_button.setEnabled(True)
        
        summary = result.summary
        
        report = (
            "=== BROWSER ANALYSIS REPORT ===\n\n"
            f"OVERVIEW\n"
            f"----------------------------------------\n"
        )
        
        if "confirmed_profile_count" in summary:
            report += (
                f"Confirmed Profiles      : {summary.get('confirmed_profile_count', 0)}\n"
                f"Inferred Profiles       : {summary.get('inferred_profile_count', 0)}\n"
                f"Unattributed Profiles   : {summary.get('unattributed_profile_count', 0)}\n"
            )
        else:
            report += f"Total Profiles Found    : {summary.get('profile_count', 0)}\n"

        if "install_scope" in summary:
            report += f"Install Scope           : {summary.get('install_scope', 'N/A')}\n"
        if "channel" in summary:
            report += f"Release Channel         : {summary.get('channel', 'N/A')}\n"

        history_profiles = summary.get('profiles_with_history', 'N/A')
        win_users = summary.get('windows_users', [])
        users_str = ', '.join(win_users) if win_users else "N/A"
        
        if history_profiles != 'N/A':
            report += f"Profiles with History   : {history_profiles}\n"
        if win_users:
            report += f"Windows Users Detected  : {users_str}\n"

        hist_records = summary.get('history_record_count', summary.get('total_visits', 0))

        report += (
            f"\nBROWSING STATISTICS\n"
            f"----------------------------------------\n"
            f"Total History Records   : {hist_records:,}\n"
            f"Total Visits            : {summary.get('total_visits', 0):,}\n"
            f"Unique URLs Visited     : {summary.get('unique_url_count', 0):,}\n"
            f"Unique Domains          : {summary.get('unique_domain_count', 0):,}\n"
        )

        if any(k in summary for k in ("bookmark_count", "download_count", "form_history_count", "cookie_count", "extension_count")):
            if "bookmark_count" in summary:
                report += f"Bookmarks Found         : {summary.get('bookmark_count', 0):,}\n"
            if "download_count" in summary:
                report += f"Downloads Logged        : {summary.get('download_count', 0):,}\n"
            if "form_history_count" in summary:
                report += f"Form History Entries    : {summary.get('form_history_count', 0):,}\n"
            if "cookie_count" in summary:
                report += f"Cookies Found           : {summary.get('cookie_count', 0):,}\n"
            if "extension_count" in summary:
                report += f"Extensions Installed    : {summary.get('extension_count', 0):,}\n"

        if "first_visit" in summary or "last_visit" in summary:
            report += (
                f"\nTIMELINE\n"
                f"----------------------------------------\n"
                f"Earliest Record         : {summary.get('first_visit', 'N/A')}\n"
                f"Most Recent Record      : {summary.get('last_visit', 'N/A')}\n"
            )
        
        self.findings_output.setPlainText(report)
        
        for p in result.profiles:
            records = getattr(p, 'history', getattr(p, 'visits', []))
            
            history_list = []
            for r in records:
                history_list.append({
                    'visit_time': getattr(r, 'visit_time', 'N/A'),
                    'url': getattr(r, 'url', ''),
                    'title': getattr(r, 'title', '')
                })
                
            history_list.sort(key=lambda x: x['visit_time'] or '', reverse=True)
            
            name = getattr(p, 'profile_name', getattr(p, 'display_name', None))
            if not name:
                name = getattr(p, 'directory_name', f"Profile {len(self.current_profiles_data)}")
            
            label = f"{name} ({getattr(p, 'windows_user', 'User')})"
            self.current_profiles_data[label] = history_list

            self.current_downloads_data[label] = [
                asdict(d) for d in getattr(p, 'downloads', [])
            ]
            
            self.current_cookies_data[label] = [
                asdict(c) for c in getattr(p, 'cookies', [])
            ]

        if self.current_profiles_data:
            self.websites_button.setEnabled(True)

        if any(self.current_downloads_data.values()):
            self.downloads_button.setEnabled(True)
            
        if any(self.current_cookies_data.values()):
            self.cookies_button.setEnabled(True)
            
    def _show_websites_window(self):
        self.websites_dialog = WebsitesWindow(self.current_profiles_data, self)
        self.websites_dialog.exec()

    def _show_downloads_window(self):
        self.downloads_dialog = DownloadsWindow(self.current_downloads_data, self)
        self.downloads_dialog.exec()


    def _show_cookies_window(self):
        self.cookies_dialog = CookiesWindow(self.current_cookies_data, self)
        self.cookies_dialog.exec()


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
        self.analyze_button.clicked.connect(self._on_analyze_clicked)

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

        self.findings_output = QPlainTextEdit("Analysis results will appear here.")
        self.findings_output.setObjectName("findingsOutput")
        self.findings_output.setReadOnly(True)

        self.websites_button = QPushButton("Websites")
        self.websites_button.setObjectName("websitesButton")
        self.websites_button.setCursor(Qt.PointingHandCursor)
        self.websites_button.setEnabled(False)
        self.websites_button.clicked.connect(self._show_websites_window)

        self.downloads_button = QPushButton("Downloads")
        self.downloads_button.setObjectName("websitesButton")
        self.downloads_button.setCursor(Qt.PointingHandCursor)
        self.downloads_button.setEnabled(False)
        self.downloads_button.clicked.connect(self._show_downloads_window)
        
        self.cookies_button = QPushButton("Cookies")
        self.cookies_button.setObjectName("websitesButton")
        self.cookies_button.setCursor(Qt.PointingHandCursor)
        self.cookies_button.setEnabled(False)
        self.cookies_button.clicked.connect(self._show_cookies_window)

        buttons_row = QHBoxLayout()
        buttons_row.setSpacing(10)
        buttons_row.addWidget(self.websites_button, 1)
        buttons_row.addWidget(self.downloads_button, 1)
        buttons_row.addWidget(self.cookies_button, 1)

        findings_layout.addWidget(findings_title)
        findings_layout.addWidget(self.findings_output, 1)
        findings_layout.addLayout(buttons_row)

        log_frame = QFrame()
        log_frame.setObjectName("panel")

        log_layout = QVBoxLayout(log_frame)
        log_layout.setContentsMargins(18, 16, 18, 16)
        log_layout.setSpacing(10)

        log_title = QLabel("Analysis Log")
        log_title.setObjectName("panelTitle")

        self.log_output = QPlainTextEdit("Analysis activity will appear here.")
        self.log_output.setObjectName("logOutput")
        self.log_output.setReadOnly(True)

        log_layout.addWidget(log_title)
        log_layout.addWidget(self.log_output, 1)

        splitter.addWidget(findings_frame)
        splitter.addWidget(log_frame)
        splitter.setSizes([1, 1])

        main_layout.addWidget(splitter, 1)
        self.statusBar().showMessage("Ready")