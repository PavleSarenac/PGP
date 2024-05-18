from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy

from backend.KeyRings import KeyRings


class ShowKeyRingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()

        self.add_title()
        self.add_dropdown_menu()
        self.add_private_key_ring_table()

        self.layout.setAlignment(Qt.AlignTop)
        self.setLayout(self.layout)

    def add_title(self):
        self.title_label = QLabel("Show key rings", self)
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(32)
        self.title_label.setFont(title_font)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignTop)

    def add_dropdown_menu(self):
        self.person_label = QLabel("Please say which user you are:", self)
        self.person_label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.layout.addWidget(self.person_label)

        self.person_dropdown_menu = QComboBox(self)
        self.person_dropdown_menu.addItem("A")
        self.person_dropdown_menu.addItem("B")
        self.layout.addWidget(self.person_dropdown_menu, alignment=Qt.AlignTop)

        self.person_dropdown_menu.currentTextChanged.connect(self.update_tables)

    def add_private_key_ring_table(self):
        self.add_private_key_ring_table_label()
        self.private_key_ring_table = QTableWidget()
        self.private_key_ring_table.setRowCount(0)
        self.private_key_ring_table.setColumnCount(7)
        self.private_key_ring_table.setHorizontalHeaderLabels([
            "user_id",
            "key_id",
            "timestamp",
            "user_name",
            "public_key_pem_format",
            "encrypted_private_key_pem_format",
            "initialization_vector"
        ])
        self.private_key_ring_table.resizeColumnsToContents()
        self.layout.addWidget(self.private_key_ring_table)
        self.populate_private_key_ring_table()

    def add_private_key_ring_table_label(self):
        self.title_label = QLabel("Private key ring", self)
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(24)
        self.title_label.setFont(title_font)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignTop)

    def populate_private_key_ring_table(self):
        person = self.person_dropdown_menu.currentText()
        all_entries = KeyRings.get_all_private_key_ring_entries(person)
        for entry in all_entries:
            self.add_row_to_private_key_ring_table(
                entry["user_id"],
                entry["key_id"],
                entry["timestamp"],
                entry["user_name"],
                entry["public_key_pem_format"],
                entry["private_key_pem_format"]["encrypted_private_key_pem_format"],
                entry["private_key_pem_format"]["initialization_vector"]
            )
        for row in range(self.private_key_ring_table.rowCount()):
            for column in range(self.private_key_ring_table.columnCount()):
                item = self.private_key_ring_table.item(row, column)
                if item:
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                    item.setData(Qt.ToolTipRole, item.text())

    def add_row_to_private_key_ring_table(
            self,
            user_id,
            key_id,
            timestamp,
            user_name,
            public_key_pem_format,
            encrypted_private_key_pem_format,
            initialization_vector
    ):
        new_row_index = self.private_key_ring_table.rowCount()
        self.private_key_ring_table.insertRow(new_row_index)

        self.private_key_ring_table.setItem(new_row_index, 0, QTableWidgetItem(user_id))
        self.private_key_ring_table.setItem(new_row_index, 1, QTableWidgetItem(key_id))
        self.private_key_ring_table.setItem(new_row_index, 2, QTableWidgetItem(timestamp))
        self.private_key_ring_table.setItem(new_row_index, 3, QTableWidgetItem(user_name))
        self.private_key_ring_table.setItem(new_row_index, 4, QTableWidgetItem(public_key_pem_format))
        self.private_key_ring_table.setItem(new_row_index, 5, QTableWidgetItem(encrypted_private_key_pem_format))
        self.private_key_ring_table.setItem(new_row_index, 6, QTableWidgetItem(initialization_vector))

    def update_tables(self):
        self.private_key_ring_table.setRowCount(0)
        self.populate_private_key_ring_table()
