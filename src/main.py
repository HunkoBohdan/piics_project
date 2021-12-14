# This Python file uses the following encoding: utf-8
import sys
import os


from PySide2.QtWidgets import QApplication, QWidget, QMessageBox, QFileDialog
from PySide2.QtCore import QFile
from PySide2.QtUiTools import QUiLoader
import PySide2

from backend import encryption_method, generate_random_sym_key, encrypt, decrypt

ui = None


class main_window(QWidget):
    def show_error(self, title, err_text):
        err_box = QMessageBox()
        err_box.setIcon(QMessageBox.Critical)
        err_box.setWindowTitle(title)
        err_box.setText(err_text)
        err_box.setStandardButtons(QMessageBox.Ok)
        err_box.setStyleSheet("font-size: 12px")
        err_box.exec()

    def set_file_path(self, window_title, element):
        file_path = QFileDialog.getOpenFileName(
            self, window_title, "c:\\")[0]
        element.setText(file_path)

    def read_from_file(self, element):
        if type(element) == PySide2.QtWidgets.QLineEdit:
            file_path = element.text()
        else:
            file_path = element.toPlainText()
        if os.path.isfile(file_path):
            with open(file_path, "r") as f:
                return f.read()

    def write_to_file(self, data):
        file_path = QFileDialog.getSaveFileName(
            self, "Select where to save file", "c:\\encrypted_msg.hex")[0]
        with open(file_path, 'wb') as f:
            f.write(data)

    def get_key_length(self, enc_method):
        return 32 if enc_method == encryption_method.Kalyna else 16

    def get_encryption_method(self):
        if ui.camellia_rb.isChecked():
            return encryption_method.Camellia
        if ui.aes_rb.isChecked():
            return encryption_method.AES
        if ui.kalyna_rb.isChecked():
            return encryption_method.Kalyna

    def get_sym_key(self, key_len):
        sym_key = ui.sym_key_line_edit.text()
        if len(sym_key) != key_len:
            return None
        return sym_key

    def get_asym_pub_key(self):
        return self.read_from_file(ui.asym_pub_key_path)

    def get_msg(self):
        if ui.msg_input_rb.isChecked():
            msg = ui.msg_line_edit.toPlainText()
            return msg if msg != "" else None

        return self.read_from_file(ui.msg_line_edit)

    def on_generate_btn_click(self):
        enc_method = self.get_encryption_method()
        sym_key_len = self.get_key_length(enc_method)
        ui.sym_key_line_edit.setText(generate_random_sym_key(sym_key_len))

    def on_asym_pub_key_btn_btn_click(self):
        self.set_file_path("Select asymmetric public key",
                           ui.asym_pub_key_path)

    def on_msg_input_rb_click(self):
        ui.msg_btn.setVisible(0)

    def on_msg_file_rb_click(self):
        ui.msg_btn.setVisible(1)

    def on_msg_btn_click(self):
        self.set_file_path("Select message file", ui.msg_line_edit)

    def on_encrypt_btn_click(self):
        enc_method = self.get_encryption_method()
        sym_key_len = self.get_key_length(enc_method)
        sym_key = self.get_sym_key(sym_key_len)
        if sym_key == None:
            self.show_error("Symmetric key length error",
                            "Key should be {} bytes long.".format(sym_key_len))
            return
        asym_pub_key = self.get_asym_pub_key()
        if asym_pub_key == None:
            self.show_error("Asymmetric key path error",
                            "Invalid path to asymmetric public key.")
            return

        msg = self.get_msg()
        if msg == None:
            if ui.msg_input_rb.isChecked():
                self.show_error("Message error",
                                "Message could not be empty.")
            else:
                self.show_error("Message file path error",
                                "Invalid path to message file.")
            return

        encrypted_msg = encrypt(asym_pub_key, enc_method, sym_key, msg)

        self.write_to_file(encrypted_msg)

    def __init__(self):
        super(main_window, self).__init__()
        self.load_ui()
        self.set_default_values()
        ui.encrypt_btn.clicked.connect(self.on_encrypt_btn_click)
        ui.generate_btn.clicked.connect(self.on_generate_btn_click)
        ui.asym_pub_key_btn.clicked.connect(self.on_asym_pub_key_btn_btn_click)
        ui.msg_input_rb.clicked.connect(self.on_msg_input_rb_click)
        ui.msg_file_rb.clicked.connect(self.on_msg_file_rb_click)
        ui.msg_btn.clicked.connect(self.on_msg_btn_click)

    def set_default_values(self):
        ui.camellia_rb.setChecked(True)
        ui.msg_file_rb.setChecked(True)

    def load_ui(self):
        loader = QUiLoader()
        path = os.path.join(os.path.dirname(__file__), "form.ui")
        ui_file = QFile(path)
        ui_file.open(QFile.ReadOnly)
        global ui
        ui = loader.load(ui_file, self)
        ui_file.close()
        self.setWindowTitle("KI-42")
        self.setFixedSize(1000, 600)


if __name__ == "__main__":
    app = QApplication([])
    widget = main_window()
    widget.show()
    sys.exit(app.exec_())
