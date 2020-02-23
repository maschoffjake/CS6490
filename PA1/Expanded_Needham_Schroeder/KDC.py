import argparse
import json
import socket
import threading

HOST = 'localhost'
PORT = 5000

# Function to pass new client connections off to
# Used to handle new key combinations
def handle_kdc(conn, address):
    name = conn.recv(1024)
    print(conn, address, name)
    while (1):
        pass
    conn.shutdown(socket.SHUT_RDWR)

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def start_server():
    print('KDC is listening...')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        (conn, address) = s.accept()
        t = threading.Thread(target=handle_kdc, args=(conn, address))
        t.daemon = True
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
        except KeyboardInterrupt:
            print('Exiting...')

if __name__ == '__main__':
    main()