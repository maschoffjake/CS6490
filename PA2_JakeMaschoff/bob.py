#
# Bob node used in the Expanded Needham Schroder protocol
#
import argparse
import socket
import sys
import threading
import json
import base64
from Crypto.Cipher import DES3
from Crypto import Random

HOST = 'localhost'
PORT = 5001

kb = b'DC8FA9EE9BA7FTTA'
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

MESSAGE_SIZE = 1024

# Function used to pass threads off to when new connections are made with bob
# Handles all of the messages in the ENS protocol for a new connection
def handle_auth(conn, address, cbc):

    # STEP 1
    recv = conn.recv(MESSAGE_SIZE)
    print('STEP 1')
    print('Received from Alice:', recv)
    print('\n')

    # STEP 2
    # Send back a random challenge... 64-bit challenges!
    rnd = Random.new()
    nb = rnd.read(8)
    
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher = DES3.new(kb, DES3.MODE_CBC, iv)
        cipher_2 = DES3.new(kb, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kb, DES3.MODE_ECB)
        cipher_2 = DES3.new(kb, DES3.MODE_ECB)


# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def start_server(cbc=False):
    print('Bob is listening...')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        (conn, address) = s.accept()
        t = threading.Thread(target=handle_auth, args=(conn, address, cbc))
        t.daemon = False
        t.start()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--ecb", action="store_true",
                    help="use ECB secret key function instead of default (CBC)")
    args = parser.parse_args()
    if args.ecb:
        print('ECB!')
        try:
            start_server()
        except Exception as e:
            print('Received exception:', e)
    else:
        print('CBC!')
        try:
            start_server(cbc=True)
        except Exception as e:
            print('Received exception:', e)

if __name__ == '__main__':
    main()