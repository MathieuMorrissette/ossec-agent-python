# MIT LICENSE

import socket
import zlib
import argparse
from argparse import RawTextHelpFormatter
from os import urandom
from hashlib import md5
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt(data, key):
    iv = b"FEDCBA0987654321" # Security Issue #1 : Static initialization vector
    padder = padding.PKCS7(128).padder()
    data = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    return cipher.update(data) + cipher.finalize()


parser = argparse.ArgumentParser(description='Send a message to a OSSEC server.\n\
Agent pass can be obtained from the client.Keys file located\n\
    in LINUX : /var/ossec/etc/client.keys\n\
    in WINDOWS : C:\\Program Files (x86)\\ossec-agent\\client.keys\n\
    in MACOS : /Library/Ossec/etc/client.keys\n\
Example command : \
    python send_ossec_msg.py 003 2301fb64635a4ca5523395d8aa7370dbbd975a22768854249366577c3d9ddf2c 8.8.8.8 1514 1 ossec "ossec: Agent started: \'hello-world-agent\'."', formatter_class=RawTextHelpFormatter)
parser.add_argument('agent_id', type=int, help='The agent id to send the message as.')
parser.add_argument('agent_pass', type=str, help='The agent pass.')
parser.add_argument('ossec_host', type=str, help='The OSSEC server host to send the message to.')
parser.add_argument('ossec_port', type=int, help='The OSSEC server host port to send the message to.')
parser.add_argument('message_queue', type=int, help='The OSSEC queue # where to send the message to (usually 1).')
parser.add_argument('message_location', type=str, help='The OSSEC message location')
parser.add_argument('message', type=str, help='The OSSEC message to send')

args = parser.parse_args()

agent_id = str(args.agent_id).encode()
md5_pass =  md5(args.agent_pass.encode()).hexdigest()

##### SECURITY ISSUE #2 #####
# Those informations are supposed to be required to generate the encryption key as per OSSEC documentation.
# After some testing they aren't required because they key gets truncated to 32 bytes anyway.
#
#md5_name = md5(b'myagent').hexdigest()
#md5_id = md5(b'003').hexdigest()
#md5_name_id = md5(md5_name.encode() + md5_id.encode()).hexdigest()[0:15]
#encryption_key = md5_pass + md5_name_id
#
##############

encryption_key = md5_pass

#####################
# OSSEC Message format <queue>:<location>:<message>
# EX : "1:ossec:ossec: Agent started: 'Somecomputername->any'."
#####################

message = str(args.message_queue).encode() + b":" + args.message_location.encode() + b":" + args.message.encode()

### BEGIN RANDOMIZE
# Generate random number between 00000 and 65535
random_number = str(int.from_bytes(urandom(2), byteorder='little', signed=False)).rjust(5, '0')

# Generate random number between 0000 and 9999
random_counter = str(int((int.from_bytes(urandom(4), byteorder='little', signed=False)/0xFFFFFFFF) * 10000)).rjust(4, '0')

message = random_number.encode() + b"0000000000:" + random_counter.encode() + b":" + message

message_sum = md5(message).hexdigest()

message = message_sum.encode() + message
### END RANDOMIZE

# Compression
after_compression = zlib.compress(message, 9)

while (len(after_compression)  % 8 != 0):
    after_compression = b"!" + after_compression

# Encryption
res = encrypt(after_compression, encryption_key.encode()[:32])

encrypted_message = b"!" + agent_id + b"!#AES:" + res

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = (args.ossec_host, args.ossec_port)
sock.connect(server_address)

encrypted_message_len = len(encrypted_message)

# Prepend TCP packet with size
little_endian_bytes = encrypted_message_len.to_bytes(4, byteorder='little')

# Send message
sock.send(little_endian_bytes + encrypted_message)

sock.close()