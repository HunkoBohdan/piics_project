from enum import Enum
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class encryption_method(Enum):
    Camellia = 1
    AES = 2
    Kalyna = 3


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


def encrypt_common(cipher, text):
    text = add_padding(text)
    encryptor = cipher.encryptor()
    return encryptor.update(text) + encryptor.finalize()


def decrypt_common(cipher, encrypted_text):
    decryptor = cipher.decryptor()
    text = decryptor.update(encrypted_text) + decryptor.finalize()
    return remove_padding(text)


def encrypt_text(enc_method, sym_key, text):
    if enc_method == encryption_method.Camellia:
        cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
        return encrypt_common(cipher, text)
    elif enc_method == encryption_method.AES:
        cipher = Cipher(algorithms.AES(sym_key), modes.ECB())
        return encrypt_common(cipher, text)


def decrypt_text(enc_method, sym_key, encrypted_text):
    if enc_method == encryption_method.Camellia:
        cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
        return decrypt_common(cipher, encrypted_text)
    elif enc_method == encryption_method.AES:
        cipher = Cipher(algorithms.AES(sym_key), modes.ECB())
        return decrypt_common(cipher, encrypted_text)


if __name__ == '__main__':
    enc_method = encryption_method.AES
    sym_key = "1234567890abcdef".encode("utf-8")
    text = "dsasdadasdsadsad123".encode("utf-8")

    encrypted_text = encrypt_text(enc_method, sym_key, text)
    decoded_text = decrypt_text(enc_method, sym_key, encrypted_text)
    print(decoded_text)
