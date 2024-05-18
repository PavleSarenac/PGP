from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QSizePolicy, QComboBox, QPlainTextEdit, QCheckBox, \
    QHBoxLayout, QSpacerItem

from backend.PGP import PGP


class SendMessagePage(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()

        self.add_title()
        self.add_input_form()

        self.setLayout(self.layout)

    def add_title(self):
        self.title_label = QLabel("Send message", self)
        self.title_label.setAlignment(Qt.AlignCenter)
        title_font = self.title_label.font()
        title_font.setPointSize(32)
        self.title_label.setFont(title_font)
        self.layout.addWidget(self.title_label, alignment=Qt.AlignTop)

    def add_input_form(self):
        self.person_label = QLabel("Please say which user you are:", self)
        self.person_label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.layout.addWidget(self.person_label)

        self.person_dropdown_menu = QComboBox(self)
        self.person_dropdown_menu.addItem("A")
        self.person_dropdown_menu.addItem("B")
        self.person_dropdown_menu.currentTextChanged.connect(self.update_key_dropdowns)
        self.layout.addWidget(self.person_dropdown_menu)

        self.plaintext = QPlainTextEdit(self)
        self.plaintext.setPlaceholderText("Please type a message...")
        self.plaintext.setFixedHeight(120)
        self.layout.addWidget(self.plaintext)

        self.add_authentication_input()

        self.compression_checkbox = QCheckBox("Compression", self)
        self.layout.addWidget(self.compression_checkbox)

        self.add_confidentiality_input()

        self.radix64_checkbox = QCheckBox("Radix64", self)
        self.layout.addWidget(self.radix64_checkbox)

    def toggle_authentication(self, state):
        is_checked = state == Qt.Checked
        self.authentication_private_keys_dropdown_menu.setEnabled(is_checked)
        self.authentication_password_input.setEnabled(is_checked)
        if not is_checked:
            self.authentication_private_keys_dropdown_menu.setCurrentIndex(0)
            self.authentication_password_input.setText("")

    def toggle_confidentiality(self, state):
        is_checked = state == Qt.Checked
        self.confidentiality_public_key_dropdown_menu.setEnabled(is_checked)
        self.confidentiality_algorithms_dropdown_menu.setEnabled(is_checked)
        if not is_checked:
            self.confidentiality_public_key_dropdown_menu.setCurrentIndex(0)
            self.confidentiality_algorithms_dropdown_menu.setCurrentIndex(0)

    def add_confidentiality_input(self):
        self.add_confidentiality_checkbox()
        self.add_confidentiality_public_key_dropdown()
        self.add_confidentiality_algorithms_dropdown()
        right_spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.confidentiality_layout.addSpacerItem(right_spacer)
        self.layout.addLayout(self.confidentiality_layout)

    def add_confidentiality_checkbox(self):
        self.confidentiality_layout = QHBoxLayout()
        self.confidentiality_checkbox = QCheckBox("Confidentiality", self)
        self.confidentiality_checkbox.stateChanged.connect(self.toggle_confidentiality)
        self.confidentiality_layout.addWidget(self.confidentiality_checkbox)

    def add_confidentiality_public_key_dropdown(self):
        self.confidentiality_public_key_dropdown_menu = QComboBox(self)
        self.confidentiality_public_key_dropdown_menu.setEnabled(False)
        person = self.person_dropdown_menu.currentText()
        all_public_key_ring_entries = PGP.get_all_public_key_ring_entries(person)
        for entry in all_public_key_ring_entries:
            self.confidentiality_public_key_dropdown_menu.addItem(
                f"PublicKey(user_id: {entry['user_id']}; key_id: {entry['key_id']})"
            )
        self.confidentiality_layout.addWidget(self.confidentiality_public_key_dropdown_menu)

    def add_confidentiality_algorithms_dropdown(self):
        self.confidentiality_algorithms_dropdown_menu = QComboBox(self)
        self.confidentiality_algorithms_dropdown_menu.setEnabled(False)
        self.confidentiality_algorithms_dropdown_menu.addItem("TripleDES")
        self.confidentiality_algorithms_dropdown_menu.addItem("AES128")
        self.confidentiality_layout.addWidget(self.confidentiality_algorithms_dropdown_menu)

    def add_authentication_input(self):
        self.add_authentication_checkbox()
        self.add_authentication_dropdown()
        self.add_authentication_password_input()
        right_spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.authentication_layout.addSpacerItem(right_spacer)
        self.layout.addLayout(self.authentication_layout)

    def add_authentication_checkbox(self):
        self.authentication_layout = QHBoxLayout()
        self.authentication_checkbox = QCheckBox("Authentication", self)
        self.authentication_checkbox.stateChanged.connect(self.toggle_authentication)
        self.authentication_layout.addWidget(self.authentication_checkbox)

    def add_authentication_dropdown(self):
        self.authentication_private_keys_dropdown_menu = QComboBox(self)
        self.authentication_private_keys_dropdown_menu.setEnabled(False)
        person = self.person_dropdown_menu.currentText()
        all_private_key_ring_entries = PGP.get_all_private_key_ring_entries(person)
        for entry in all_private_key_ring_entries:
            self.authentication_private_keys_dropdown_menu.addItem(
                f"PrivateKey(user_id: {entry['user_id']}; key_id: {entry['key_id']})"
            )
        self.authentication_layout.addWidget(self.authentication_private_keys_dropdown_menu)

    def add_authentication_password_input(self):
        self.authentication_password_input = QLineEdit(self)
        self.authentication_password_input.setPlaceholderText("Please enter the password...")
        self.authentication_password_input.setEnabled(False)
        self.authentication_password_input.setEchoMode(QLineEdit.Password)
        self.authentication_layout.addWidget(self.authentication_password_input)

    def update_key_dropdowns(self):
        self.update_authentication_dropdown()
        self.update_confidentiality_dropdown()

    def update_authentication_dropdown(self):
        person = self.person_dropdown_menu.currentText()
        all_private_key_ring_entries = PGP.get_all_private_key_ring_entries(person)
        self.authentication_private_keys_dropdown_menu.clear()
        for entry in all_private_key_ring_entries:
            self.authentication_private_keys_dropdown_menu.addItem(
                f"PrivateKey(user_id: {entry['user_id']}; key_id: {entry['key_id']})"
            )

    def update_confidentiality_dropdown(self):
        person = self.person_dropdown_menu.currentText()
        all_public_key_ring_entries = PGP.get_all_public_key_ring_entries(person)
        self.confidentiality_public_key_dropdown_menu.clear()
        for entry in all_public_key_ring_entries:
            self.confidentiality_public_key_dropdown_menu.addItem(
                f"PublicKey(user_id: {entry['user_id']}; key_id: {entry['key_id']})"
            )

    def send_message(self):
        pass
