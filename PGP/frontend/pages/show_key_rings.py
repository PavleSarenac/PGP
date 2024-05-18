from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QComboBox, QSizePolicy, \
    QPushButton, QInputDialog, QDialog
from backend.PGP import PGP
from frontend.utils.message_box import MessageBox
from frontend.utils.password_input_dialog import PasswordInputDialog


class ShowKeyRingsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()

        self.add_title()
        self.add_dropdown_menu()
        self.add_private_key_ring_table()
        self.add_public_key_ring_table()

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
        self.private_key_ring_table.setColumnCount(8)
        self.private_key_ring_table.setHorizontalHeaderLabels([
            "user_id",
            "key_id",
            "timestamp",
            "user_name",
            "public_key_pem_format",
            "encrypted_private_key_pem_format",
            "initialization_vector",
            "delete_row"
        ])
        self.private_key_ring_table.resizeColumnsToContents()
        self.layout.addWidget(self.private_key_ring_table)
        self.populate_private_key_ring_table()

    def add_public_key_ring_table(self):
        self.add_public_key_ring_table_label()
        self.public_key_ring_table = QTableWidget()
        self.public_key_ring_table.setRowCount(0)
        self.public_key_ring_table.setColumnCount(5)
        self.public_key_ring_table.setHorizontalHeaderLabels([
            "user_id",
            "key_id",
            "timestamp",
            "user_name",
            "public_key_pem_format"
        ])
        self.public_key_ring_table.resizeColumnsToContents()
        self.layout.addWidget(self.public_key_ring_table)
        self.populate_public_key_ring_table()

    def add_private_key_ring_table_label(self):
        self.title_label = QLabel("Private key ring", self)
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(24)
        self.title_label.setFont(title_font)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignTop)

    def add_public_key_ring_table_label(self):
        self.title_label = QLabel("Public key ring", self)
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(24)
        self.title_label.setFont(title_font)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignTop)

    def populate_private_key_ring_table(self):
        person = self.person_dropdown_menu.currentText()
        all_entries = PGP.get_private_key_ring(person)
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

    def populate_public_key_ring_table(self):
        person = self.person_dropdown_menu.currentText()
        all_entries = PGP.get_public_key_ring(person)
        for entry in all_entries:
            self.add_row_to_public_key_ring_table(
                entry["user_id"],
                entry["key_id"],
                entry["timestamp"],
                entry["user_name"],
                entry["public_key_pem_format"]
            )
        for row in range(self.public_key_ring_table.rowCount()):
            for column in range(self.public_key_ring_table.columnCount()):
                item = self.public_key_ring_table.item(row, column)
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

        delete_row_button = QPushButton("Delete")
        delete_row_button.clicked.connect(lambda: self.delete_private_key_ring_row(delete_row_button))
        self.private_key_ring_table.setCellWidget(new_row_index, 7, delete_row_button)

    def delete_private_key_ring_row(self, delete_row_button):
        row_index = self.private_key_ring_table.indexAt(delete_row_button.pos()).row()
        person_deleting = self.person_dropdown_menu.currentText()
        person_affected = "B" if person_deleting == "A" else "A"
        user_id = self.private_key_ring_table.item(row_index, 0).text()
        key_id = self.private_key_ring_table.item(row_index, 1).text()
        password_dialog = PasswordInputDialog(self)
        if password_dialog.exec_() == QDialog.Accepted:
            private_key_password = password_dialog.get_password()
            if PGP.delete_rsa_key_pair_from_private_key_ring(
                    person_deleting,
                    person_affected,
                    user_id,
                    key_id,
                    private_key_password
            ):
                MessageBox.show_success_message_box("Selected key pair was successfully deleted!")
                self.private_key_ring_table.removeRow(row_index)
            else:
                MessageBox.show_error_message_box("Incorrect password!")

    def add_row_to_public_key_ring_table(
            self,
            user_id,
            key_id,
            timestamp,
            user_name,
            public_key_pem_format
    ):
        new_row_index = self.public_key_ring_table.rowCount()
        self.public_key_ring_table.insertRow(new_row_index)

        self.public_key_ring_table.setItem(new_row_index, 0, QTableWidgetItem(user_id))
        self.public_key_ring_table.setItem(new_row_index, 1, QTableWidgetItem(key_id))
        self.public_key_ring_table.setItem(new_row_index, 2, QTableWidgetItem(timestamp))
        self.public_key_ring_table.setItem(new_row_index, 3, QTableWidgetItem(user_name))
        self.public_key_ring_table.setItem(new_row_index, 4, QTableWidgetItem(public_key_pem_format))

    def update_tables(self):
        self.private_key_ring_table.setRowCount(0)
        self.public_key_ring_table.setRowCount(0)
        self.populate_private_key_ring_table()
        self.populate_public_key_ring_table()
