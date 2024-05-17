from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QComboBox, QSizePolicy


class GenerateNewRsaKeyPairPage(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout()

        self.add_title()
        self.add_input_form()

        self.setLayout(self.layout)

    def add_title(self):
        title_label = QLabel("Generate new RSA key pair", self)
        title_label.setAlignment(Qt.AlignCenter)
        title_font = title_label.font()
        title_font.setPointSize(32)
        title_label.setFont(title_font)
        self.layout.addWidget(title_label, alignment=Qt.AlignTop)

    def add_input_form(self):
        user_name_input_field = QLineEdit(self)
        user_name_input_field.setPlaceholderText("Please enter your name...")
        self.layout.addWidget(user_name_input_field)

        user_email_input_field = QLineEdit(self)
        user_email_input_field.setPlaceholderText("Please enter your email...")
        self.layout.addWidget(user_email_input_field)

        rsa_key_size_label = QLabel("Please choose RSA key size in bits:", self)
        rsa_key_size_label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Fixed)
        self.layout.addWidget(rsa_key_size_label)

        rsa_key_size_dropdown_menu = QComboBox(self)
        rsa_key_size_dropdown_menu.addItem("1024")
        rsa_key_size_dropdown_menu.addItem("2048")
        self.layout.addWidget(rsa_key_size_dropdown_menu)

        user_password_input_field = QLineEdit(self)
        user_password_input_field.setPlaceholderText("Please enter your password...")
        self.layout.addWidget(user_password_input_field)
