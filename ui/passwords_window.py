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


class PasswordsWindow(QDialog):
    COLUMNS = ["Website", "Username", "Password"]

    def __init__(self, profiles_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Saved Passwords")
        self.resize(1100, 700)
        self.setMinimumSize(800, 500)

        self.profiles_data = profiles_data
        self.current_passwords = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        chooser_row = QHBoxLayout()
        chooser_row.setSpacing(12)

        chooser_label = QLabel("Select Profile")
        chooser_label.setObjectName("fieldLabel")

        self.profile_combo = QComboBox()
        for label, passwords in profiles_data.items():
            self.profile_combo.addItem(f"{label}  -  {len(passwords):,} password(s)", label)

        self.ok_button = QPushButton("OK")
        self.ok_button.setCursor(Qt.PointingHandCursor)
        self.ok_button.clicked.connect(self._on_ok_clicked)
        self.ok_button.setEnabled(self.profile_combo.count() > 0)

        chooser_row.addWidget(chooser_label)
        chooser_row.addWidget(self.profile_combo, 1)
        chooser_row.addWidget(self.ok_button)
        layout.addLayout(chooser_row)

        self.status_label = QLabel("Choose a profile and click OK to view its saved passwords.")
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
        header.setStretchLastSection(True)
        self.table.setColumnWidth(0, 300)
        self.table.setColumnWidth(1, 250)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)

        details_frame = QVBoxLayout()
        details_title = QLabel("Password Details")
        details_title.setObjectName("panelTitle")
        self.details_output = QPlainTextEdit("Click a password entry above to see more information.")
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

        self.current_passwords = self.profiles_data.get(label, [])
        self.details_output.setPlainText("Click a password entry above to see more information.")

        self.table.setUpdatesEnabled(False)
        self.table.clearSelection()
        self.table.setRowCount(len(self.current_passwords))
        for row, p in enumerate(self.current_passwords):
            cells = [
                p.get("hostname") or "(unknown)",
                p.get("username") or "(empty)",
                p.get("password") or "(empty)",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                self.table.setItem(row, col, item)
        self.table.setUpdatesEnabled(True)

        if self.current_passwords:
            self.status_label.setText(
                f"{len(self.current_passwords):,} saved password(s) found for {label}. "
                "Click one for details."
            )
        else:
            self.status_label.setText(
                f"No saved passwords found for {label}."
            )

    def _on_selection_changed(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        index = rows[0].row()
        if 0 <= index < len(self.current_passwords):
            self.details_output.setPlainText(self._format_details(self.current_passwords[index]))

    @staticmethod
    def _format_details(p):
        def val(key, default="N/A"):
            value = p.get(key)
            return str(value) if value not in (None, "") else default

        lines = [
            "SAVED LOGIN",
            "-" * 40,
            f"{'Website':<15}: {val('hostname')}",
            f"{'Username':<15}: {val('username')}",
            f"{'Password':<15}: {val('password')}",
            f"{'Profile':<15}: {val('profile')}",
        ]

        return "\n".join(lines)

