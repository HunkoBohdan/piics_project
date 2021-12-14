from backend import encryption_method, generate_random_sym_key, encrypt, decrypt
import os

if __name__ == '__main__':
    enc_method = encryption_method.Kalyna
    sym_key = generate_random_sym_key(32)
    text = "some sample text here"

    script_dir = os.path.dirname(__file__)

    rsa_pub_key = open(os.path.join(
        script_dir, "dummy_keys/rsa.pem.pub"), 'r').read()
    rsa_priv_key = open(os.path.join(
        script_dir, "dummy_keys/rsa.pem"), 'r').read()

    encrypted_msg = encrypt(rsa_pub_key, enc_method, sym_key, text)
    decrypted_msg = decrypt(rsa_priv_key, encrypted_msg)
    print(decrypted_msg)
