from Crypto.PublicKey import RSA
import os
import rsa
from base64 import b64decode,b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def load_private_key(key_file, key_password=None):
    """
    Load a private key from disk.

    :param key_file: File path to key file.
    :param key_password: Optional. If the key file is encrypted, provide the password to decrypt it. Defaults to None.
    :return: PrivateKey<string>
    """
    key_file = os.path.expanduser(key_file)
    key_file = os.path.abspath(key_file)

    if not key_password:
        with open(key_file, 'r') as key:
            return key.read()

    with open(key_file, 'rb') as key:
        key_bytes = key.read()
    return decrypt_key(key_bytes, key_password).decode(ENCODING) 

privKey = load_private_key("/Users/admin/Downloads/minikube/ingress.key")
pubKey = load_private_key("/Users/admin/Downloads/minikube/public.key")
keyPriv = rsa.PrivateKey.load_pkcs1(privKey.encode())
keyPub = RSA.importKey(pubKey.encode())


encMessage = "fzSsgjWVnHY98YkJa79xbNxF4nxwwL+cNhnPEl220mC2qBYmU5eHwek/fpuRRYXdfnA3X7NHY4hOD2C5ih1jP1eJT0lcssqZer1Fk7fPf0Dsr3rk7aiC08u61Xl3KK174Mug0IGpKbl87LhaobZrkjAjodSyeK/blvPkZAlkKorfpC9OHBPiG7++VOH9jbvwDJiAgjz2DByEYvo1IC54ogfXzm5ca4jxS6ZA7c8Sx4cHB/YW/m5/17F2s+CDwSzRUgi4/O725rPYrfIHjabvWSOYKaNtF9CmzNbEWzBCVGmThwx9YANAHwgi9LUAVfFbU+yKxtLoDXkbhLd1hsvu8Q=="
encMessage = b64decode(encMessage)

with open("/Users/admin/Downloads/minikube/ingress.key", "rb") as key_file:
    privKey = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )
print("Clave privada: ", privKey)

original_message = privKey.decrypt(
    encMessage,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print('Original: ', original_message)



