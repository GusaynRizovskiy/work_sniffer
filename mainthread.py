import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLabel
from PyQt5.QtCore import QThread, pyqtSignal

class Worker(QThread):
    update_signal = pyqtSignal(str)

    def run(self):
        while True:
            self.update_signal.emit("Цикл выполняется...")
            self.msleep(1000)  # Пауза в 1 секунду

class MyApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.worker = Worker()
        self.worker.update_signal.connect(self.update_label)

    def initUI(self):
        layout = QVBoxLayout()

        self.label = QLabel('Ожидание...', self)
        layout.addWidget(self.label)

        self.start_button = QPushButton('Запустить цикл', self)
        self.start_button.clicked.connect(self.start_thread)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton('Остановить цикл', self)
        self.stop_button.clicked.connect(self.stop_thread)
        layout.addWidget(self.stop_button)

        self.setLayout(layout)
        self.setWindowTitle('Бесконечный цикл в PyQt5')
        self.setGeometry(100, 100, 300, 200)
        self.show()

    def start_thread(self):
        if not self.worker.isRunning():
            self.worker.start()

    def stop_thread(self):
        if self.worker.isRunning():
            self.worker.terminate()  # Остановка потока

    def update_label(self, text):
        self.label.setText(text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())
