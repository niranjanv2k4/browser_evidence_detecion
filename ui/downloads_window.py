from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def _human_size(num_bytes):
    if not num_bytes or num_bytes <= 0:
        return "Unknown"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def _duration(start, end):
    try:
        delta = datetime.strptime(end, TIME_FORMAT) - datetime.strptime(start, TIME_FORMAT)
    except (TypeError, ValueError):
        return "N/A"
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "N/A"
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


class DownloadsWindow(QDialog):
    """
    profiles_data: {"<profile label>": [download dict, ...]}
    The download dicts come from dataclasses.asdict(DownloadRecord).
    """

    COLUMNS = ["File Name", "Started", "Size", "Status", "Source URL"]

    def __init__(self, profiles_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Downloads")
        self.resize(1100, 700)
        self.setMinimumSize(800, 500)

        self.profiles_data = profiles_data
        self.current_downloads = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        # --- Profile chooser row -------------------------------------------
        chooser_row = QHBoxLayout()
        chooser_row.setSpacing(12)

        chooser_label = QLabel("Select Profile")
        chooser_label.setObjectName("fieldLabel")

        self.profile_combo = QComboBox()
        for label, downloads in profiles_data.items():
            self.profile_combo.addItem(f"{label}  -  {len(downloads):,} download(s)", label)

        self.ok_button = QPushButton("OK")
        self.ok_button.setCursor(Qt.PointingHandCursor)
        self.ok_button.clicked.connect(self._on_ok_clicked)
        self.ok_button.setEnabled(self.profile_combo.count() > 0)

        chooser_row.addWidget(chooser_label)
        chooser_row.addWidget(self.profile_combo, 1)
        chooser_row.addWidget(self.ok_button)
        layout.addLayout(chooser_row)

        self.status_label = QLabel("Choose a profile and click OK to view its downloads.")
        layout.addWidget(self.status_label)

        # --- Downloads table + details pane --------------------------------
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 280)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        details_frame = QVBoxLayout()
        details_title = QLabel("Download Details")
        details_title.setObjectName("panelTitle")
        self.details_output = QPlainTextEdit("Click a download above to see more information.")
        self.details_output.setReadOnly(True)
        self.details_output.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.details_output.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))

        details_widget = QWidget()
        details_frame.setContentsMargins(0, 0, 0, 0)
        details_frame.addWidget(details_title)
        details_frame.addWidget(self.details_output, 1)
        details_widget.setLayout(details_frame)

        splitter.addWidget(self.table)
        splitter.addWidget(details_widget)
        splitter.setSizes([350, 250])
        layout.addWidget(splitter, 1)

        close_row = QHBoxLayout()
        close_row.addStretch()
        close_button = QPushButton("Close")
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.clicked.connect(self.accept)
        close_row.addWidget(close_button)
        layout.addLayout(close_row)

    # ------------------------------------------------------------------ slots
    def _on_ok_clicked(self):
        label = self.profile_combo.currentData()
        if label is None:
            return

        self.current_downloads = self.profiles_data.get(label, [])
        self.details_output.setPlainText("Click a download above to see more information.")

        self.table.setUpdatesEnabled(False)
        self.table.clearSelection()
        self.table.setRowCount(len(self.current_downloads))
        for row, d in enumerate(self.current_downloads):
            cells = [
                d.get("file_name") or "(unknown)",
                d.get("start_time") or "N/A",
                _human_size(d.get("total_bytes") or d.get("received_bytes")),
                d.get("state") or "Unknown",
                d.get("url") or d.get("tab_url") or "",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, col, item)
        self.table.setUpdatesEnabled(True)

        if self.current_downloads:
            self.status_label.setText(
                f"{len(self.current_downloads):,} download(s) recorded for {label} "
                "(newest first). Click one for details."
            )
        else:
            self.status_label.setText(
                f"No downloads recorded for {label}. (A missing record is not proof "
                "that nothing was downloaded; history may have been cleared.)"
            )

    def _on_selection_changed(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        index = rows[0].row()
        if 0 <= index < len(self.current_downloads):
            self.details_output.setPlainText(self._format_details(self.current_downloads[index]))

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _format_details(d):
        """Build the details text. Browsers store different amounts of information
        (Chromium keeps much more than Firefox), so a field is only shown when the
        record actually has that key. A key that is present but empty shows 'N/A'."""

        def val(key, default="N/A"):
            value = d.get(key)
            return value if value not in (None, "") else default

        lines = []

        def section(title, rows):
            rows = [(label, text) for label, key, text in rows if key is None or key in d]
            if not rows:
                return
            if lines:
                lines.append("")
            lines.extend([title, "-" * 40])
            for label, text in rows:
                lines.append(f"{label:<19}: {text}")

        # ---- size text -----------------------------------------------------
        received = d.get("received_bytes") or 0
        total = d.get("total_bytes") or 0
        if "received_bytes" in d:
            size_text = f"{_human_size(received)} ({received:,} bytes)"
            if total > 0:
                size_text += f" of {_human_size(total)} ({total:,} bytes)"
        else:
            size_text = f"{_human_size(total)} ({total:,} bytes)" if total > 0 else "Unknown"

        section("FILE", [
            ("File Name", "file_name", val("file_name")),
            ("Saved To", "target_path", val("target_path")),
            ("Temp/Current Path", "current_path", val("current_path")),
            ("Size", "total_bytes" if "received_bytes" not in d else None, size_text),
            ("MIME Type", "mime_type", val("mime_type")),
            ("Original MIME Type", "original_mime_type", val("original_mime_type")),
        ])
        section("STATUS", [
            ("State", "state", val("state")),
            ("Danger Type", "danger_type", val("danger_type")),
            ("Interrupt Reason", "interrupt_reason", val("interrupt_reason")),
            ("Opened by User", "opened", "Yes" if d.get("opened") else "No"),
        ])
        section("TIMELINE", [
            ("Download Started", "start_time", val("start_time")),
            ("Download Ended", "end_time", val("end_time")),
            ("Duration", "end_time" if "start_time" in d else "start_time",
             _duration(d.get("start_time"), d.get("end_time"))),
            ("Last Accessed", "last_access_time", val("last_access_time")),
        ])
        section("SOURCE", [
            ("Download URL", "url", val("url")),
            ("Referrer", "referrer", val("referrer")),
            ("Site URL", "site_url", val("site_url")),
            ("Tab URL", "tab_url", val("tab_url")),
            ("Tab Referrer URL", "tab_referrer_url", val("tab_referrer_url")),
        ])
        chain = d.get("url_chain")
        if "url_chain" in d:
            lines.append("URL Chain (incl. redirects):")
            lines.append("\n".join(f"  {i}. {u}" for i, u in enumerate(chain, 1)) if chain else "  N/A")
        section("HTTP / TECHNICAL", [
            ("HTTP Method", "http_method", val("http_method")),
            ("ETag", "etag", val("etag")),
            ("Last-Modified", "last_modified", val("last_modified")),
            ("Started By Ext.", "by_extension", val("by_extension")),
            ("Download ID", "download_id", val("download_id")),
            ("GUID", "guid", val("guid")),
            ("Profile", "profile", val("profile")),
        ])
        extra = d.get("extra")
        if isinstance(extra, dict) and extra:
            section("ADDITIONAL", [(k, None, v) for k, v in extra.items()])
        return "\n".join(lines)