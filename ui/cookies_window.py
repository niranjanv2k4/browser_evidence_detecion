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


class CookiesWindow(QDialog):
    COLUMNS = ["Host", "Name", "Path", "Created"]

    def __init__(self, profiles_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Cookies")
        self.resize(1100, 700)
        self.setMinimumSize(800, 500)

        self.profiles_data = profiles_data
        self.current_cookies = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        chooser_row = QHBoxLayout()
        chooser_row.setSpacing(12)

        chooser_label = QLabel("Select Profile")
        chooser_label.setObjectName("fieldLabel")

        self.profile_combo = QComboBox()
        for label, cookies in profiles_data.items():
            self.profile_combo.addItem(f"{label}  -  {len(cookies):,} cookie(s)", label)

        self.ok_button = QPushButton("OK")
        self.ok_button.setCursor(Qt.PointingHandCursor)
        self.ok_button.clicked.connect(self._on_ok_clicked)
        self.ok_button.setEnabled(self.profile_combo.count() > 0)

        chooser_row.addWidget(chooser_label)
        chooser_row.addWidget(self.profile_combo, 1)
        chooser_row.addWidget(self.ok_button)
        layout.addLayout(chooser_row)

        self.status_label = QLabel("Choose a profile and click OK to view its cookies.")
        layout.addWidget(self.status_label)

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
        header.setSectionResizeMode(1, QHeaderView.Interactive)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 200)
        self.table.setColumnWidth(2, 150)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        details_frame = QVBoxLayout()
        details_title = QLabel("Cookie Details")
        details_title.setObjectName("panelTitle")
        self.details_output = QPlainTextEdit("Click a cookie above to see more information.")
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

    def _on_ok_clicked(self):
        label = self.profile_combo.currentData()
        if label is None:
            return

        self.current_cookies = self.profiles_data.get(label, [])
        self.details_output.setPlainText("Click a cookie above to see more information.")

        self.table.setUpdatesEnabled(False)
        self.table.clearSelection()
        self.table.setRowCount(len(self.current_cookies))
        for row, c in enumerate(self.current_cookies):
            cells = [
                c.get("host") or "(unknown)",
                c.get("name") or "(unknown)",
                c.get("path") or "/",
                c.get("creation_time") or "N/A",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, col, item)
        self.table.setUpdatesEnabled(True)

        if self.current_cookies:
            self.status_label.setText(
                f"{len(self.current_cookies):,} cookie(s) recorded for {label} "
                "Click one for details."
            )
        else:
            self.status_label.setText(
                f"No cookies recorded for {label}."
            )

    def _on_selection_changed(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        index = rows[0].row()
        if 0 <= index < len(self.current_cookies):
            self.details_output.setPlainText(self._format_details(self.current_cookies[index]))

    @staticmethod
    def _format_details(c):
        def val(key, default="N/A"):
            value = c.get(key)
            return str(value) if value not in (None, "") else default

        lines = []

        def section(title, rows):
            rows = [(label, text) for label, key, text in rows if key is None or key in c]
            if not rows:
                return
            if lines:
                lines.append("")
            lines.extend([title, "-" * 40])
            for label, text in rows:
                lines.append(f"{label:<19}: {text}")

        section("IDENTIFICATION", [
            ("Host", "host", val("host")),
            ("Name", "name", val("name")),
            ("Path", "path", val("path")),
            ("Profile", "profile", val("profile")),
        ])
        
        section("TIMELINE", [
            ("Created (UTC)", "creation_time", val("creation_time")),
            ("Expires (UTC)", "expiry_time", val("expiry_time")),
        ])
        
        section("SECURITY FLAGS", [
            ("Secure", "is_secure", "Yes" if c.get("is_secure") else "No"),
            ("HttpOnly", "is_httponly", "Yes" if c.get("is_httponly") else "No"),
        ])
        
        return "\n".join(lines)