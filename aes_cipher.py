#Student ID: 260201009

import sys
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import *
from Crypto.Random import get_random_bytes

text_message = ""
password = ""
key_length = 0
file_name = ""

op_type = sys.argv[1]

try:
    for i in range(len(sys.argv)):
        if sys.argv[i] == "-m":
            text_message = sys.argv[i + 1]
        elif sys.argv[i] == "-p":
            password = sys.argv[i + 1]
        elif sys.argv[i] == "-k":
            key_length = int(sys.argv[i + 1])
        elif sys.argv[i] == "-f":
            file_name = sys.argv[i + 1]
except ValueError:
    print("String cannot be converted into integer!")

if key_length in [16, 24, 32]:
    if op_type == "enc":
        salting = get_random_bytes(16)
        key = scrypt(password, salting, key_length, (2 ** 14), 16, 1)
        padded_data = pad(bytes(text_message, 'utf-8'), 16)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_data)
        file = open(file_name, "w")
        info = {"salt": b64encode(salting).decode('utf-8'),
                "iv": b64encode(iv).decode('utf-8'),
                "ciphertext": b64encode(ciphertext).decode('utf-8')}
        print("Encryption result:", info)
        file.write(json.dumps(info))
        file.close()
    elif op_type == "dec":
        file = open(file_name, "r")
        info = json.loads(file.readline())
        salting = bytes(info["salt"], 'utf-8')
        iv = bytes(info["iv"], 'utf-8')
        ciphertext = bytes(info["ciphertext"], 'utf-8')
        file.close()
        key = scrypt(password, b64decode(salting), key_length, (2 ** 14), 16, 1)
        cipher = AES.new(key, AES.MODE_CBC, b64decode(iv))
        text_message = unpad(cipher.decrypt(b64decode(ciphertext)), 16)
        print("Plaintext:", str(text_message,'utf-8'))
    else:
        print("Invalid Operation!")
else:
    print("Incorrect AES key length!")