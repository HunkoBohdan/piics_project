# This Python file uses the following encoding: utf-8
import sys
import os


from PySide2.QtWidgets import QApplication, QWidget
from PySide2.QtCore import QFile
from PySide2.QtUiTools import QUiLoader

ui = None


class main_window(QWidget):
    def __init__(self):
        super(main_window, self).__init__()
        self.load_ui()

    def load_ui(self):
        loader = QUiLoader()
        path = os.path.join(os.path.dirname(__file__), "form.ui")
        ui_file = QFile(path)
        ui_file.open(QFile.ReadOnly)
        global ui
        ui = loader.load(ui_file, self)
        ui_file.close()
        self.setWindowTitle("KI-42");
        self.setFixedSize(1000, 600)


if __name__ == "__main__":
    app = QApplication([])
    widget = main_window()
    widget.show()
    sys.exit(app.exec_())
