import argparse
import json
import socket
import threading
import sys
import base64
from Crypto.Cipher import DES3

HOST = 'localhost'
PORT = 5000

MESSAGE_SIZE = 1024
SIZE_OF_NONCES = 8  # In bytes
SIZE_OF_KEYS = 16   # In bytes

ka = b'6CCD4EE1B2B37A8C'
kb = b'DC8FA9EE9BA7FTTA'
kab = b'1A7852E45997CNCA'
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'


# Map used to store what int means who is requesting and requester
clients = {
    1: 'Alice',
    2: 'Bob'
}

# Function to pass new client connections off to
# Used to handle new key combinations
def handle_kdc(conn, address, ecb=False):

    # Just received JSON object, so deserialize it
    json_str = conn.recv(MESSAGE_SIZE)
    data = json.loads(json_str)
    requester_val = data['requester']
    requesting_val = data['requesting']
    print('STEP 3:')
    print('Received from', clients[requester_val], ':', data)
    print('\n')

    # Create the appropiate cipher to encrypt and decrypt
    # Requesting val of 2 means 
    if ecb:
        cipher_alice = DES3.new(ka, DES3.MODE_ECB)
        cipher_bob = DES3.new(kb, DES3.MODE_ECB)
    else:
        cipher_alice = DES3.new(ka, DES3.MODE_CBC, iv)
        cipher_bob = DES3.new(kb, DES3.MODE_CBC, iv)

    # Now send back the nonce, the name val, the actual key value, and ticket for respective server
    data_to_send = {}
    data_to_send['nonce'] = data['nonce']
    data_to_send['name'] = clients[requesting_val]
    data_to_send['kab'] = kab.decode('utf-8')

    # Create ticket
    ticket = {}
    ticket['kab'] = kab.decode('utf-8')
    ticket['name'] = requester_val
    ticket['nb'] = data['encrypted_nonce']

    # Pad the string in case it isn't 8-bytes... Just pad with '.  values and remove 
    string_to_pad = json.dumps(ticket)
    while (len(string_to_pad) % 8 != 0):
        string_to_pad += '0'
    # Check to see if we are encrypting with Alice's key (1) of Bob's key (2)
    if requesting_val == 1:
        encrypted_ticet = cipher_alice.encrypt(string_to_pad)
    else:
        encrypted_ticet = cipher_bob.encrypt(string_to_pad)
    data_to_send['ticket'] = base64.encodebytes(encrypted_ticet).decode('ascii')

    # Send the data back to requester
    json_to_send = json.dumps(data_to_send)
    # Pad the string in case it isn't 8-bytes... Just pad with ' ' values and remove 
    while (len(json_to_send) % 8 != 0):
        json_to_send += ' '
    json_to_send = json_to_send.encode('utf-8')
    
    val_sending = cipher_alice.encrypt(json_to_send)
    print('STEP 4:')
    print('Created ticket:', string_to_pad)
    print('Encrypted ticket:', encrypted_ticet)
    print('Encoded ticket:', data_to_send['ticket'])
    print('KDC sending to', clients[requester_val], ':', json_to_send)
    print('Ecnrypted:', val_sending)
    print('\n')
    conn.sendall(val_sending)

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def start_server(ecb):
    print('KDC is listening...')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        (conn, address) = s.accept()
        t = threading.Thread(target=handle_kdc, args=(conn, address, ecb))
        t.daemon = True
        t.start()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--ecb", action="store_true",
                    help="use ECB secret key function instead of default (CBC)")
    args = parser.parse_args()
    if args.ecb:
        print('ECB!')
        start_server(True)
    else:
        print('CBC!')
        try:
            start_server(False)
        except KeyboardInterrupt:
            print('Exiting...')

if __name__ == '__main__':
    main()