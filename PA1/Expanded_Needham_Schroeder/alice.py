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
    s.connect(('127.0.0.1', 5000))
    s.send(name)
    data = s.recv(1024)
    result = json.loads(data)
    print(json.dumps(result, indent=4))

def main():

    # Client socket code:
    client(b'1')


if __name__ == "__main__":
    main()