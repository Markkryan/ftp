'''
A file transfer program beween client and server
Server side
Marc Bondoc
10098545


'''

import socket
import sys
import argparse
import time
import random
import hashlib
import os
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


'''
Returns the time in hr:min:sec
'''
def time_stamp():
    t = time.localtime()
    stamp = str(t[3]) + ":" + str(t[4]) + ":" + str(t[5]) + ": "
    return stamp

'''
Computes the hash to compare with client response
'''
def compute_hash(challenge, nonce, key):
    hashf = hashlib.sha1()
    message = challenge + nonce + key
    hashf.update(message.encode())
    generated_hash = hashf.hexdigest()
    return generated_hash

'''
Generates a random challenge
'''

def generate_challenge():
    hashf = hashlib.sha1()
    seed = str(random.randint(0, 100000))
    hashf.update(seed.encode())
    challenge = hashf.hexdigest()
    return challenge

'''
Sends challenge to client and receives the response if response == generated_hash then returns true otherwise false
'''
def authenticate(client, cipher_type, nonce, key, sk=None, iv=None):
    response = None
    if cipher_type == "null":
        challenge = generate_challenge()
        generated_hash = compute_hash(challenge[:14], nonce, key)
        #client.send(challenge[:14].encode())
        length = padding_message(str(len(challenge[:14])).encode())
        send_message(client, length)
        send_message(client, challenge[:14].encode())
        response = recv_message(client)

    else:
        challenge = generate_challenge()
        generated_hash = compute_hash(challenge[:14], nonce, key)
        '''
        encrypts the challenge
        '''
        encrypted_challenge = encrypt_data(challenge[:14].encode(), sk, iv)
        #print("encrypted_challenge={}".format(encrypted_challenge))
        length = padding_message(str(len(encrypted_challenge)).encode())
        send_message(client, length)
        send_message(client, encrypted_challenge)
        encrypted_response = recv_message(client)
        response = decrypt_data(encrypted_response, sk, iv)
        #print("response={}".format(response.decode()))
    if response[:15].decode() == generated_hash[:15]:
        return True
    else:
        return False

'''
Pads messages
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
Taken from https://docs.python.org/3/howto/sockets.html
'''
def send_message(client, message):
    total = 0
    length = len(message)
    while total < length:
        sent = client.send(message[total:])
        total = total + sent
'''
Taken from https://docs.python.org/3/howto/sockets.html
Receives messages from client
'''
def recv_message(client, cipher="null"):
    c = []
    num_bytes = 0
    #Will keep receiving until buffer is full
    while num_bytes < 16:
        cs = client.recv(16 - num_bytes)
        #print("chunk={} chunk_length={}".format(cs, len(cs)))
        c.append(unpadding_message(cs))
        num_bytes = num_bytes + len(cs)
    #Receives the length of the message inc
    length = b''.join(c)
    length = int(length.decode())

    #Returns the actually message
    c = []
    num_bytes = 0
    while num_bytes < length:
        cs = client.recv(length - num_bytes)
        c.append(cs)
        num_bytes = num_bytes + len(cs)
        #print("length_chunks={} length_chunk={} num_bytes={}".format(len(c), len(cs), num_bytes))
    return b''.join(c)

'''
Breakpoint to control where to stop
'''
def breakpoint():
    client_socket.close()
    server_socket.close()
    sys.exit(0)    

'''
Taken from https://pages.cpsc.ucalgary.ca/~henrique.pereira/pdfs/advanced_encrypt.py
Decrypts ciphertext and unpads message
'''
def decrypt_data(ciphertext, sk, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

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
Receives input from client and writes to file
'''
def download(file_name, client, cipher_type, sk=None, iv=None):
    stamp = time_stamp()
    try:
        if cipher_type == "null":
            with open(file_name, "wb") as f:

                length = padding_message(str(len("OK")).encode())
                send_message(client, length)
                send_message(client, b"OK")

                content = None
                while content != b'':
                    content = recv_message(client)
                    f.write(content)
            print(stamp + "status: success")

        else:
            with open(file_name, "wb") as f:

                ok_msg = encrypt_data(b"OK", sk, iv)
                length = padding_message(str(len(ok_msg)).encode())
                send_message(client, length)
                send_message(client, ok_msg)
                content = None
                while content != b'':
                    content = recv_message(client)
                    if content != b'':
                        plaintext = decrypt_data(content, sk, iv)
                        f.write(plaintext)
                    else:
                        f.write(b'')
            print(stamp + "status: success")

    except Exception as err:
        print(stamp + "status: failure")
        print("Error: {}".format(err))
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))
        if cipher_type == "null":
            ok_msg = "NO"
            length = padding_message(str(len(ok_msg)).encode())
            send_message(client, length)
            send_message(client, ok_msg)
        else:
            ok_msg = encrypt_data(b"NO", sk, iv)
            length = padding_message(str(len(ok_msg)).encode())
            send_message(client, length)
            send_message(client, ok_msg)

'''
Reads file on server side and sends file to client
'''
def upload(file_name, client, cipher_type, sk=None, iv=None):
    stamp = time_stamp()
    try:
        if cipher_type == "null":
            with open(file_name, "rb") as f:
                length = padding_message(str(len("OK")).encode())
                send_message(client, length)
                send_message(client, b"OK")

                content = None
                while content != b'':
                    content = f.read(16)
                    length = padding_message(str(len(content)).encode())
                    send_message(client, length)
                    send_message(client, content)
                f.close()
            print(stamp + "status: success")
        else:
            with open(file_name, "rb") as f:

                ok_msg = encrypt_data(b"OK", sk, iv)
                length = padding_message(str(len(ok_msg)).encode())
                send_message(client, length)
                send_message(client, ok_msg)

                content = None
                while content !=b'':
                    content = f.read(15)
                    ciphertext = encrypt_data(content, sk, iv)
                    length = padding_message(str(len(ciphertext)).encode())
                    send_message(client, length)
                    send_message(client, ciphertext)
            print(stamp + "status: success")

    except Exception as err:
        print(stamp + "status: failure")
        print("Error: {}".format(err))
        print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))
        if cipher_type == "null":
            ok_msg = "NO"
            length = padding_message(str(len(ok_msg)).encode())
            send_message(client, length)
            send_message(client, ok_msg)
        else:
            ok_msg = encrypt_data(b"NO", sk, iv)
            length = padding_message(str(len(ok_msg)).encode())
            send_message(client, length)
            send_message(client, ok_msg)


parser = argparse.ArgumentParser(description='Server for downloading and uploading files')
parser.add_argument('port', type=int, help='Port number')
parser.add_argument('key', help='Secret key')
args = parser.parse_args()

port = args.port
key = args.key

print("Listening on port {}".format(port))
print("Using secret key: {}".format(key))

server_socket = socket.socket()
server_socket.bind(('', port))
server_socket.listen(0)


try:
    while True:
        print("Waiting for a client...")

        client_socket, info = server_socket.accept()
        stamp = time_stamp()
        print(stamp + "new connection from {}".format(info))
        first_msg = recv_message(client_socket)
        print(first_msg)
        
        first_msg = first_msg.decode().split(" ")
        cipher_type = first_msg[0].lower()
        nonce = first_msg[1]
        print(stamp + "cipher={}".format(cipher_type))
        print(stamp + "nonce={}".format(nonce))

        
        #Generates a random value to share with the client to compute session key and IV
        i_iv = os.urandom(16)
        i_sk = os.urandom(16)
        #Decodes messages to send to client
        i_iv = b64encode(i_iv).decode('utf8')
        length = padding_message(str(len(i_iv)).encode())
        send_message(client_socket, length)
        send_message(client_socket, i_iv.encode())

        i_sk = b64encode(i_sk).decode('utf8')
        length = padding_message(str(len(i_sk)).encode())
        send_message(client_socket, length)
        send_message(client_socket, i_sk.encode())

        
        if cipher_type == "null":
            print(stamp + "authenicating...")
            #Checks if the client has the proper key
            authorize = authenticate(client_socket, cipher_type, nonce, key)
            if authorize == True:
                print(stamp + "status: key confirmed")
                
                length = padding_message(str(len("True")).encode())
                send_message(client_socket, length)
                send_message(client_socket, b"True")

                action = recv_message(client_socket)
                action = action.decode().split(" ")
                command = action[0].lower()
                file_name = action[1]
                print(stamp + "command={}".format(command))
                print(stamp + "file_name={}".format(file_name))

                if command == "write":
                    download(file_name, client_socket, cipher_type)
                    client_socket.close()
                elif command == "read":
                    upload(file_name, client_socket, cipher_type)
                    client_socket.close()
            else:
                print(stamp + "status: key denied")
                client_socket.close()

        else:
            hashf = hashlib.sha256()

            #generates the IV
            seed = key + nonce[:16] + i_iv
            hashf.update(seed.encode())
            iv = hashf.hexdigest()
            iv = iv[:16].encode()
            print(stamp + "IV={}".format(iv.decode()))

            #generates the session key for aes128 and aes256
            seed = key + nonce[:16] + i_sk
            hashf.update(seed.encode())
            sk = hashf.hexdigest()

            #128 bit key
            if cipher_type == "aes128":
                sk = sk[:16].encode()
                print(stamp + "SK={}".format(sk.decode()))

            #256 bit key
            else:
                sk = sk[:32].encode()
                print(stamp + "SK={}".format(sk.decode()))
            
            print(stamp + "authenicating...")
            authorize = authenticate(client_socket, cipher_type, nonce, key, sk, iv)

            
            if authorize == True:
                print(stamp + "status: key confirmed")
                confirm = encrypt_data(b"True", sk, iv)
                length = padding_message(str(len(confirm)).encode())
                send_message(client_socket, length)
                send_message(client_socket, confirm)

                command = recv_message(client_socket)
                command = decrypt_data(command, sk, iv).decode()
                file_name = recv_message(client_socket)
                file_name = decrypt_data(file_name, sk, iv).decode()
                print(stamp + "command={}".format(command))
                print(stamp + "file_name={}".format(file_name))

                if command == "read":
                    upload(file_name, client_socket, cipher_type, sk, iv)
                    client_socket.close()
                elif command == "write":
                    download(file_name, client_socket, cipher_type, sk, iv)
                    client_socket.close()

except Exception as err:
    print("Exception Occured: {}.".format(err))
    print('Error on line {}'.format(sys.exc_info()[-1].tb_lineno))
    pass

server_socket.close()
