#
#

import socket
import sys
import json

HOST = 'localhost'
PORT = 8000

MESSAGE_SIZE = 1024

def client(name):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 5001))
    s.send(name)
    data = s.recv(1024)
    print(data)

def main():

    # Client socket code:
    client(b'1')


if __name__ == "__main__":
    main()