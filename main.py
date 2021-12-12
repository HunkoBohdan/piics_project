from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from kalyna_cipher.classEncryption import classEncryption
from kalyna_cipher.classDecryption import classDecryption
from kalyna_cipher.classRound import classRound
from kalyna_cipher.classBasic import classBasic
from kalyna_cipher.classKey import classKey


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


def from_bytes_to_hex_string(bytes_arr):
    return "".join("{:02x}".format(byte) for byte in bytes_arr)


def from_hex_string_to_bytes(string):
    return bytearray.fromhex(string)


def encrypt_common(cipher, text):
    text = add_padding(text)
    encryptor = cipher.encryptor()
    return encryptor.update(text) + encryptor.finalize()


def decrypt_common(cipher, encrypted_text):
    decryptor = cipher.decryptor()
    text = decryptor.update(encrypted_text) + decryptor.finalize()
    return remove_padding(text).decode("utf-8")


def encrypt_kalyna(sym_key, text):
    sym_key = from_bytes_to_hex_string(sym_key)
    text = add_padding(text)
    text = from_bytes_to_hex_string(text)
    converter = classBasic()
    encryptor = classEncryption(False)

    encrypted_text = ""
    for i in range(0, int(len(text)/32)):
        text_chunk = text[i * 32: i * 32 + 32]
        encrypted_text_chunk = encryptor.func_encrypt(
            converter.func_string_to_mas(text_chunk), converter.func_string_to_mas(sym_key))
        encrypted_text += converter.func_matrix_to_string(encrypted_text_chunk)
    return encrypted_text.encode("utf-8")


def decrypt_kalyna(sym_key, encrypted_text):
    sym_key = from_bytes_to_hex_string(sym_key)
    converter = classBasic()
    decryptor = classDecryption(False)

    text = ""
    for i in range(0, int(len(encrypted_text)/32)):
        encrypted_text_chunk = encrypted_text[i * 32: i * 32 + 32]
        text_chunk = decryptor.func_decrypt(
            converter.func_string_to_mas(encrypted_text_chunk.decode("utf-8")), converter.func_string_to_mas(sym_key))
        text += converter.func_matrix_to_string(text_chunk)
    text = from_hex_string_to_bytes(text)
    return remove_padding(text).decode("utf-8")


def encrypt_text(enc_method, sym_key, text):
    if enc_method == encryption_method.Camellia:
        cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
        return encrypt_common(cipher, text)
    elif enc_method == encryption_method.AES:
        cipher = Cipher(algorithms.AES(sym_key), modes.ECB())
        return encrypt_common(cipher, text)
    elif enc_method == encryption_method.Kalyna:
        return encrypt_kalyna(sym_key, text)


def decrypt_text(enc_method, sym_key, encrypted_text):
    if enc_method == encryption_method.Camellia:
        cipher = Cipher(algorithms.Camellia(sym_key), modes.ECB())
        return decrypt_common(cipher, encrypted_text)
    elif enc_method == encryption_method.AES:
        cipher = Cipher(algorithms.AES(sym_key), modes.ECB())
        return decrypt_common(cipher, encrypted_text)
    elif enc_method == encryption_method.Kalyna:
        return decrypt_kalyna(sym_key, encrypted_text)


if __name__ == '__main__':
    enc_method = encryption_method.Camellia
    sym_key = "1234567890abcdef".encode("utf-8")
    text = "1234567890abcdef1234567890abcdef1234567890abcdef".encode("utf-8")

    encrypted_text = encrypt_text(enc_method, sym_key, text)
    decoded_text = decrypt_text(enc_method, sym_key, encrypted_text)

    print(encrypted_text)
    print(decoded_text)
