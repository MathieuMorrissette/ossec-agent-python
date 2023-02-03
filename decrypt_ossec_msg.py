# MIT LICENSE

import zlib
import os
from os import urandom
from hashlib import md5, sha256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes




# The pass can be retrieved in the client.keys file.
# in LINUX : /var/ossec/etc/client.keys
# in WINDOWS : C:\\Program Files (x86)\\ossec-agent\\client.keys
# in MACOS : /Library/Ossec/etc/client.keys

# or generated using the agent manager.
agent_id = b"184" # agent id
md5_pass =  md5(os.environ["OSSEC_PASS"].encode()).hexdigest()
encryption_key = md5_pass 

def decrypt(data, key):
    iv = b"FEDCBA0987654321" # Security Issue
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    data = cipher.update(data) + cipher.finalize()
    padder = padding.PKCS7(128).unpadder()
    return padder.update(data) + padder.finalize()

data_to_decrypt = ()

decrypted = decrypt(data_to_decrypt, encryption_key.encode()[:32])


while decrypted[0] == 33: # !
    decrypted = decrypted[1:]

zlib.decompress(decrypted)

print(decrypted)
