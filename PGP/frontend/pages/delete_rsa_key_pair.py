from PyQt5.QtWidgets import QWidget, QVBoxLayout


class DeleteRsaKeyPairPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        self.setLayout(layout)
