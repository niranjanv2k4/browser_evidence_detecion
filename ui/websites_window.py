from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QComboBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
)

class WebsitesWindow(QDialog):
    def __init__(self, profiles_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Visited Websites History")
        self.resize(850, 600)
        
        # profiles_data is a dictionary: {"Profile Name": [list of records]}
        self.profiles_data = profiles_data

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(20, 20, 20, 20)

        # --- Top Row: Dropdown and OK Button ---
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

        top_layout.addWidget(self.profile_combo, 1)
        top_layout.addWidget(self.ok_button)
        
        layout.addLayout(top_layout)

        # --- Data Table ---
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Visit Time (UTC)", "URL", "Title"])
        
        # Make the URL column stretch to fill space
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)

        layout.addWidget(self.table, 1)

    def _on_ok_clicked(self):
        profile_name = self.profile_combo.currentText()
        if not profile_name:
            return
            
        history = self.profiles_data.get(profile_name, [])
        
        # Clear existing table data
        self.table.setRowCount(0)
        
        # Populate table
        for i, record in enumerate(history):
            self.table.insertRow(i)
            
            time_item = QTableWidgetItem(record.get('visit_time', 'N/A'))
            url_item = QTableWidgetItem(record.get('url', ''))
            title_item = QTableWidgetItem(record.get('title', ''))
            
            self.table.setItem(i, 0, time_item)
            self.table.setItem(i, 1, url_item)
            self.table.setItem(i, 2, title_item)