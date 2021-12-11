from enum import Enum
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class encoding_method(Enum):
    Camellia = 1
    AES = 2
    Kalina = 3


def add_padding(data, size=128):
    padder = padding.PKCS7(size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def remove_padding(data, size=128):
    padder = padding.PKCS7(size).unpadder()
    unpadded_data = padder.update(data)
    unpadded_data += padder.finalize()
    return unpadded_data


def encrypt_camellia(sym_key, text):
    text = add_padding(text)
    cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(text) + encryptor.finalize()


def decrypt_camellia(sym_key, encrypted_text):
    cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
    decryptor = cipher.decryptor()
    text = decryptor.update(encrypted_text) + decryptor.finalize()
    return remove_padding(text)


def encrypt_text(enc_method, sym_key, text):
    if enc_method == encoding_method.Camellia:
        return encrypt_camellia(sym_key, text)


def decrypt_text(enc_method, sym_key, encrypted_text):
    if enc_method == encoding_method.Camellia:
        return decrypt_camellia(sym_key, encrypted_text)


if __name__ == '__main__':
    enc_method = encoding_method.Camellia
    sym_key = "1234567890abcdef".encode("utf-8")
    text = "dsasdadasdsadsad".encode("utf-8")

    encrypted_text = encrypt_text(enc_method, sym_key, text)
    decoded_text = decrypt_text(enc_method, sym_key, encrypted_text)
    print(decoded_text)
