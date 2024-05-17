import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QAction

from frontend.pages.delete_rsa_key_pair import DeleteRsaKeyPairPage
from frontend.pages.generate_new_rsa_key_pair import GenerateNewRsaKeyPairPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.resize(1200, 800)
        self.setWindowTitle("PGP")

        self.stacked_widget = QStackedWidget()
        self.page_1 = GenerateNewRsaKeyPairPage()
        self.page_2 = DeleteRsaKeyPairPage()
        self.stacked_widget.addWidget(self.page_1)
        self.stacked_widget.addWidget(self.page_2)
        self.setCentralWidget(self.stacked_widget)

        menu_bar = self.menuBar()
        menu_choose_service = menu_bar.addMenu("Choose a service")

        page_1_action = QAction("Generate new RSA key pair", self)
        page_1_action.triggered.connect(self.show_page_1)
        menu_choose_service.addAction(page_1_action)

        page_2_action = QAction("Delete RSA key pair", self)
        page_2_action.triggered.connect(self.show_page_2)
        menu_choose_service.addAction(page_2_action)

    def show_page_1(self):
        self.stacked_widget.setCurrentWidget(self.page_1)

    def show_page_2(self):
        self.stacked_widget.setCurrentWidget(self.page_2)


def main():
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
