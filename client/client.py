'''
A file transfer program between client and server
Client side
Marc Bondoc
10098545
'''


import socket
import sys
import hashlib
import argparse
import random
import sys
import os
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


'''
Computes the hash to send to the server
'''
def compute_hash(challenge, nonce, key):
    hashf = hashlib.sha1()
    message = challenge + nonce + key
    hashf.update(message.encode())
    generated_hash = hashf.hexdigest()
    return generated_hash

'''
pads messages
'''

def padding_message(message):
    padder = padding.PKCS7(128).padder()
    data = padder.update(message) + padder.finalize()
    return data
'''
unpads messages
'''
def unpadding_message(message):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(message) + unpadder.finalize()
    return data

'''
taken from https://docs.python.org/3/howto/sockets.html
continously sends message if there are more bytes to send
'''
def send_message(s, message):
    total = 0
    #print("message={}".format(message))
    length = len(message)
    while total < length:
        sent = s.send(message[total:])
        #print("#num_bytes_sent={}".format(sent))
        total = total + sent


'''
taken from https://docs.python.org/3/howto/sockets.html
Receives the length of the message first then the actual message
'''

def recv_message(s, cipher="null"):
    c = []
    num_bytes = 0
    
    while num_bytes < 16:
        cs = s.recv(16 - num_bytes)
        c.append(unpadding_message(cs))
        num_bytes = num_bytes + len(cs)
    length = b''.join(c)
    length = int(length.decode())

    c = []
    num_bytes = 0
    while num_bytes < length:
        cs = s.recv(length - num_bytes)
        c.append(cs)
        num_bytes = num_bytes + len(cs)
    return b''.join(c)

'''
controls where the program stops
'''
def breakpoint():
    sys.exit(0)  

'''
Taken from https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/advanced_encrypt.py
Encrypts plaintext + padding
'''
def encrypt_data(message, sk, iv):
    ciphertext = b''
    if message != b'':
        backend = default_backend()
        cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        data = padder.update(message) + padder.finalize()
        ciphertext = encryptor.update(data) + encryptor.finalize()
    return ciphertext

'''
Taken from https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/advanced_encrypt.py
Decrypts ciphertext and unpads message
'''
def decrypt_data(ciphertext, sk, iv):
    plaintext = b''
    if ciphertext != b'':
        backend = default_backend()
        cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        #print("decrypted data = {}".format(decrypted_data))
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    #print("unpadded data = {}".format(plaintext))
    #print("num_bytes={}MB".format(num_bytes/1048576))
    return plaintext

'''
Receives file from server and writes to file
'''
def download(file_name, s, cipher_type, sk=None, iv=None):
    try:
        if cipher_type == "null":
            with open(file_name, "wb") as f:
                content = None
                while content != b'':
                    content = recv_message(s)
                    f.write(content)
                f.close()
        else:
            with open(file_name, "wb") as f:
                content = None
                while content != b'':
                    content = recv_message(s)
                    if content != b'':
                        plaintext = decrypt_data(content, sk, iv)
                        f.write(plaintext)
                    else:
                        f.write(b'')
                f.close()
    except Exception as err:
        print("Error: {}".format(err))
        print("Error on line {}".format(sys.exc_info()[-1].tb_lineno))


'''
Reads from file on client side and sends to server
'''
def upload(s, cipher_type, sk=None, iv=None):
    try:
        if cipher_type == "null":
            content = None
            while content != b'':
                content = sys.stdin.buffer.read(16)
                length = padding_message(str(len(content)).encode())
                send_message(s, length)
                send_message(s, content)
        else:
            content = None
            while content != b'':
                content = sys.stdin.buffer.read(15)
                ciphertext = encrypt_data(content, sk, iv)
                length = padding_message(str(len(ciphertext)).encode())
                send_message(s, length)
                send_message(s, ciphertext)
    except Exception as err:
        print("Error: {}".format(err))
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))


parser = argparse.ArgumentParser(description="Client side to upload and download files")
parser.add_argument('command', help="write/read")
parser.add_argument('filename', help="file name")
parser.add_argument('host_port', help="host name : port #")
parser.add_argument('cipher', help="cipher used")
parser.add_argument('key', help="key")
args = parser.parse_args()

command = args.command
filename = args.filename
host_port = args.host_port
host_port = host_port.split(":")
host = host_port[0]
port = int(host_port[1])
cipher_type = args.cipher
key = args.key

#Checks if args is valid
accepted_commands = {"write", "read"}
accepted_cipher = {"null", "aes128", "aes256"}
if command in accepted_commands and cipher_type in accepted_cipher:
        s = socket.socket()
        s.connect((host, port))
else: 
    print("Error: bad argument")
    sys.exit(0)

#generates a random nonce and sends to server
hashf = hashlib.sha1()
seed = str(random.randint(0, 100000))
hashf.update(seed.encode())
nonce = hashf.hexdigest().upper()

first_msg = cipher_type + " " + nonce[:16]
length = padding_message(str(len(first_msg)).encode())
send_message(s, length)
send_message(s, first_msg.encode())

i_iv = recv_message(s).decode()
i_sk = recv_message(s).decode()
#print("'IV'={} 'SK'={}".format(i_iv, i_sk))

if cipher_type == "null":

    challenge = recv_message(s)
    response = compute_hash(challenge.decode(), nonce[:16], key)
    length = padding_message(str(len(response)).encode())
    send_message(s, length)
    send_message(s, response.encode())

    access = recv_message(s)
    if access.decode() == "True":
        print("Access granted")
        action = command + " " + filename
        length = padding_message(str(len(action)).encode())
        send_message(s, length)
        send_message(s, action.encode())

        if command == "write":
            confirm = recv_message(s)
            print("Uploading")
            if confirm.decode() == "OK":
                upload(s, cipher_type)
                print(confirm.decode())
            else:
                print("Error: file could not be written by server")
                sys.exit(0)

        elif command == "read":
            confirm = recv_message(s)
            print("Downloading")
            if confirm.decode() == "OK":
                download(filename, s, cipher_type)
                print(confirm.decode())
            else:
                print("Error: file could not be written by server")
                sys.exit(0)
    else:
        print("Error: wrong key")

elif cipher_type == "aes128" or cipher_type == "aes256":
    hashf = hashlib.sha256()

    seed = key + nonce[:16] + i_iv

    hashf.update(seed.encode())
    iv = hashf.hexdigest()
    iv = iv[:16].encode()

    seed = key + nonce[:16] + i_sk
    hashf.update(seed.encode())
    sk = hashf.hexdigest()

    if cipher_type == "aes128":
        sk = sk[:16].encode()
    else:
        sk = sk[:32].encode()

    challenge = recv_message(s, cipher_type)
    #print("challenge={} length={}".format(challenge, len(challenge)))
    response = compute_hash(decrypt_data(challenge, sk, iv).decode(), nonce[:16], key)
    #print("response={}".format(response))
    encrypted_response = encrypt_data(response.encode(), sk, iv)
    length = padding_message(str(len(encrypted_response)).encode())
    send_message(s, length)
    send_message(s, encrypted_response)

    access = recv_message(s)
    access = decrypt_data(access, sk, iv)
    if access.decode() == "True":
        print("Access granted")
    
        #s.send(encrypt_data(command.encode(), sk, iv))
        length = padding_message(str(len(encrypt_data(command.encode(), sk, iv))).encode())
        send_message(s, length)
        send_message(s, encrypt_data(command.encode(), sk, iv))
        #s.send(encrypt_data(filename.encode(), sk, iv))

        length = padding_message(str(len(encrypt_data(filename.encode(), sk, iv))).encode())
        send_message(s, length)
        send_message(s, encrypt_data(filename.encode(), sk, iv))

        if command == "write":

            print("Uploading")
            confirm = recv_message(s)
            confirm = decrypt_data(confirm, sk, iv)

            if confirm.decode() == "OK":
                upload(s, cipher_type, sk, iv)
                print(confirm.decode())
            else:
                print("Error: file could not be written by server")
                sys.exit(0)

        elif command == "read":

            print("Downloading")

            confirm = recv_message(s)
            confirm = decrypt_data(confirm, sk, iv)

            if confirm.decode() == "OK":
                download(filename, s, cipher_type, sk, iv)
                print(confirm.decode())
            else:
                print("Error: file could not be read by server")
                sys.exit(0)



