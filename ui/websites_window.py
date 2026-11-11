from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtGui import QFontDatabase
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QComboBox,
    QCheckBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSplitter,
    QLabel,
    QPlainTextEdit,
    QWidget,
    QAbstractItemView
)

# Optional: pip install tldextract
# Groups subdomains under their registered domain (mail.google.com -> google.com).
# Without it, the fallback uses the hostname minus "www.".
try:
    import tldextract
    _tld = tldextract.TLDExtract(suffix_list_urls=())  # offline, bundled suffix list
except ImportError:
    _tld = None


def get_site(url):
    if _tld:
        registered = _tld(url).registered_domain
        if registered:
            return registered
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        host = ""
    return host.removeprefix("www.") or "(no domain)"


class WebsitesWindow(QDialog):
    def __init__(self, profiles_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Visited Websites History")
        self.resize(850, 600)

        # profiles_data is a dictionary: {"Profile Name": [list of records]}
        self.profiles_data = profiles_data
        self.current_history = []  # Store the currently displayed profile's history
        self.display_rows = []     # Rows currently shown (URL records or domain groups)

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # --- Top Row: Dropdown, Group checkbox and OK Button ---
        top_layout = QHBoxLayout()
        top_layout.setSpacing(10)

        self.profile_combo = QComboBox()
        self.profile_combo.setPlaceholderText("Select a profile...")
        for profile_name in self.profiles_data.keys():
            self.profile_combo.addItem(profile_name)

        self.ok_button = QPushButton("OK")
        self.ok_button.setCursor(Qt.PointingHandCursor)
        self.ok_button.setMinimumHeight(38)
        self.ok_button.setMinimumWidth(80)
        self.ok_button.clicked.connect(self._on_ok_clicked)

        self.group_checkbox = QCheckBox("Group by domain")
        self.group_checkbox.toggled.connect(self._populate_table)

        top_layout.addWidget(self.profile_combo, 1)
        top_layout.addWidget(self.group_checkbox)
        top_layout.addWidget(self.ok_button)

        layout.addLayout(top_layout)

        # --- Splitter for Table and Details Pane ---
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)

        # --- Data Table ---
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Last Visit Time (UTC)", "URL", "Title"])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Interactive)

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        # --- Details Pane ---
        details_frame = QVBoxLayout()
        details_title = QLabel("Website Details")

        self.details_output = QPlainTextEdit("Click a website above to see more information.")
        self.details_output.setReadOnly(True)
        self.details_output.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.details_output.setFont(QFontDatabase.systemFont(QFontDatabase.FixedFont))

        details_widget = QWidget()
        details_frame.setContentsMargins(0, 0, 0, 0)
        details_frame.addWidget(details_title)
        details_frame.addWidget(self.details_output, 1)
        details_widget.setLayout(details_frame)

        # Add widgets to splitter
        splitter.addWidget(self.table)
        splitter.addWidget(details_widget)
        splitter.setSizes([350, 150])  # Default height ratio for table vs details

        layout.addWidget(splitter, 1)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _get(record, key, default=None):
        """Read a field from either a dict or an object."""
        if isinstance(record, dict):
            return record.get(key, default)
        return getattr(record, key, default)

    def _group_by_domain(self, history):
        groups = {}
        for r in history:
            site = get_site(self._get(r, 'url', ''))
            g = groups.setdefault(site, {
                'domain': site,
                'visit_count': 0,
                'url_count': 0,
                'visit_time': None,
                'first_visit_time': None,
                'profile': self._get(r, 'profile', 'N/A'),
            })
            g['visit_count'] += int(self._get(r, 'visit_count', 0) or 0)
            g['url_count'] += 1

            last = self._get(r, 'visit_time')
            first = self._get(r, 'first_visit_time')
            if last and (g['visit_time'] is None or last > g['visit_time']):
                g['visit_time'] = last
            if first and (g['first_visit_time'] is None or first < g['first_visit_time']):
                g['first_visit_time'] = first

        return sorted(groups.values(), key=lambda g: g['visit_count'], reverse=True)

    # ------------------------------------------------------------------ slots
    def _on_ok_clicked(self):
        profile_name = self.profile_combo.currentText()
        if not profile_name:
            return

        self.current_history = self.profiles_data.get(profile_name, [])
        self._populate_table()

    def _populate_table(self):
        by_domain = self.group_checkbox.isChecked()
        self.display_rows = (self._group_by_domain(self.current_history)
                             if by_domain else self.current_history)

        self.table.setHorizontalHeaderLabels(
            ["Last Visit Time (UTC)", "Domain", "Total Visits"] if by_domain
            else ["Last Visit Time (UTC)", "URL", "Title"])
        self.details_output.setPlainText("Click a website above to see more information.")

        self.table.setUpdatesEnabled(False)
        self.table.clearSelection()
        self.table.setRowCount(0)

        for i, rec in enumerate(self.display_rows):
            v_time = self._get(rec, 'visit_time') or 'N/A'
            if by_domain:
                col1, col2 = rec['domain'], str(rec['visit_count'])
            else:
                col1, col2 = self._get(rec, 'url', ''), self._get(rec, 'title', '')

            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(str(v_time)))
            self.table.setItem(i, 1, QTableWidgetItem(str(col1)))
            self.table.setItem(i, 2, QTableWidgetItem(str(col2)))

        self.table.setUpdatesEnabled(True)

    def _on_selection_changed(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return

        index = rows[0].row()
        if 0 <= index < len(self.display_rows):
            rec = self.display_rows[index]
            if self.group_checkbox.isChecked():
                self.details_output.setPlainText(self._format_domain_details(rec))
            else:
                self.details_output.setPlainText(self._format_details(rec))

    # ------------------------------------------------------------------ formatting
    @staticmethod
    def _format_details(record):
        is_dict = isinstance(record, dict)

        title = record.get('title', 'N/A') if is_dict else getattr(record, 'title', 'N/A')
        url = record.get('url', 'N/A') if is_dict else getattr(record, 'url', 'N/A')
        last_visit = record.get('visit_time', 'N/A') if is_dict else (getattr(record, 'visit_time', None) or 'N/A')
        first_visit = record.get('first_visit_time', 'N/A') if is_dict else (getattr(record, 'first_visit_time', None) or 'N/A')
        # Default is 'N/A' (not 0) so a missing key is visible instead of looking like a real zero
        visit_count = record.get('visit_count', 'N/A') if is_dict else getattr(record, 'visit_count', 'N/A')
        profile = record.get('profile', 'N/A') if is_dict else getattr(record, 'profile', 'N/A')

        lines = [
            "WEBSITE INFORMATION",
            "-" * 40,
            f"{'Title':<15}: {title}",
            f"{'URL':<15}: {url}",
            "",
            "VISIT DATA",
            "-" * 40,
            f"{'Visit Count':<15}: {visit_count} time(s)",
            f"{'First Visited':<15}: {first_visit or 'N/A'}",
            f"{'Last Visited':<15}: {last_visit}",
            f"{'Profile':<15}: {profile}"
        ]

        return "\n".join(lines)

    @staticmethod
    def _format_domain_details(g):
        lines = [
            "DOMAIN INFORMATION",
            "-" * 40,
            f"{'Domain':<15}: {g['domain']}",
            "",
            "VISIT DATA",
            "-" * 40,
            f"{'Total Visits':<15}: {g['visit_count']}",
            f"{'Unique URLs':<15}: {g['url_count']}",
            f"{'First Visited':<15}: {g['first_visit_time'] or 'N/A'}",
            f"{'Last Visited':<15}: {g['visit_time'] or 'N/A'}",
            f"{'Profile':<15}: {g['profile']}",
        ]
        return "\n".join(lines)