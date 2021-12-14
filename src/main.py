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
    def show_msg_box(self, title, text, icon=QMessageBox.Critical):
        err_box = QMessageBox()
        err_box.setIcon(icon)
        err_box.setWindowTitle(title)
        err_box.setText(text)
        err_box.setStandardButtons(QMessageBox.Ok)
        err_box.setStyleSheet("font-size: 12px")
        err_box.exec()

    def set_file_path(self, window_title, element):
        file_path = QFileDialog.getOpenFileName(
            self, window_title, "c:\\")[0]
        element.setText(file_path)

    def read_from_file(self, element, mode="r"):
        if type(element) == PySide2.QtWidgets.QLineEdit:
            file_path = element.text()
        else:
            file_path = element.toPlainText()
        if os.path.isfile(file_path):
            with open(file_path, mode) as f:
                return f.read()

    def write_to_file(self, data, filename,  mode="w"):
        file_path = QFileDialog.getSaveFileName(
            self, "Select where to save file", os.path.join("c:\\", filename))[0]
        with open(file_path, mode) as f:
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

    def get_asym_priv_key(self):
        return self.read_from_file(ui.asym_priv_key_path)

    def get_msg(self):
        if ui.msg_input_rb.isChecked():
            msg = ui.msg_line_edit.toPlainText()
            return msg if msg != "" else None

        return self.read_from_file(ui.msg_line_edit)

    def get_encrypted_msg(self):
        return self.read_from_file(ui.encrypted_msg_path, "rb")

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

    def on_asym_priv_key_btn_click(self):
        self.set_file_path(
            "Select asymmetric private key file", ui.asym_priv_key_path)

    def on_encrypted_file_btn_click(self):
        self.set_file_path(
            "Select encrypted message file", ui.encrypted_msg_path)

    def on_encrypt_btn_click(self):
        enc_method = self.get_encryption_method()
        sym_key_len = self.get_key_length(enc_method)
        sym_key = self.get_sym_key(sym_key_len)
        if sym_key == None:
            self.show_msg_box("Symmetric key length error",
                              "Key should be {} bytes long.".format(sym_key_len))
            return
        asym_pub_key = self.get_asym_pub_key()
        if asym_pub_key == None:
            self.show_msg_box("Asymmetric public key path error",
                              "Invalid path to asymmetric public key.")
            return

        msg = self.get_msg()
        if msg == None:
            if ui.msg_input_rb.isChecked():
                self.show_msg_box("Message error",
                                  "Message could not be empty.")
            else:
                self.show_msg_box("Message file path error",
                                  "Invalid path to message file.")
            return

        encrypted_msg = encrypt(asym_pub_key, enc_method, sym_key, msg)
        self.write_to_file(encrypted_msg, "encrypted_msg.hex", "wb")
        self.show_msg_box("Encryption done", "Encryption done",
                          QMessageBox.Information)

    def on_decrypt_btn_click(self):
        asym_priv_key = self.get_asym_priv_key()
        if asym_priv_key == None:
            self.show_msg_box("Asymmetric private key path error",
                              "Invalid path to asymmetric private key.")
            return
        encrypted_msg = self.get_encrypted_msg()
        if encrypted_msg == None:
            self.show_msg_box("Encrypted message error",
                              "Invalid path to encrypted message file.")
            return

        msg = decrypt(asym_priv_key, encrypted_msg)
        self.write_to_file(msg, "msg.txt")
        self.show_msg_box("Decryption done", "Decryption done",
                          QMessageBox.Information)

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
        ui.asym_priv_key_btn.clicked.connect(self.on_asym_priv_key_btn_click)
        ui.encrypted_file_btn.clicked.connect(self.on_encrypted_file_btn_click)
        ui.decrypt_btn.clicked.connect(self.on_decrypt_btn_click)

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
