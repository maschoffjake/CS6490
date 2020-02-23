#
# Bob node used in the Expanded  Needham 
#
import argparse
import socket
import sys
import threading
import json
from Crypto.Cipher import DES

HOST = 'localhost'
PORT = 5001

kb = b'4DB7CAA9A2B14'

MESSAGE_SIZE = 1024

def handle_auth():
    
    # Send back a random challenge...

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def start_server():
    print('Bob is listening...')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        (conn, address) = s.accept()
        t = threading.Thread(target=handle_auth)
        t.daemon = False
        t.start()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--ecb", action="store_true",
                    help="use ECB secret key function instead of default (CBC)")
    args = parser.parse_args()
    if args.ecb:
        print('ECB!')
    else:
        print('CBC!')
        try:
            start_server()
        except Exception as e:
            print('Received exception:', e)

if __name__ == '__main__':
    main()