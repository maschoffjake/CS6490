#
# Create the Alice client that is used in the extended needham-schroeder protocol
#

import socket
import sys
import json
from Crypto import Random
from Crypto.Cipher import DES3

HOST = 'localhost'
PORT_BOB = 5001
PORT_KDC = 5000

MESSAGE_SIZE = 1024

ka = b'6CCD4EE1B2B37A8C'
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

def main():

    # First send to Bob a 1, tell him that Alice wants to communicate with them
    msg = bytes([1])
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    s_bob.send(msg)
    print('Alice sent to Bob:', msg)

    # Receive the nonce encrypted by Bob, and send it to the KDC
    encrypt_nonce = s_bob.recv(MESSAGE_SIZE)
    print('Alice received from Bob:', encrypt_nonce)
    s_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_kdc.connect((HOST, PORT_KDC))
    
    # Create a nonce to send along with this message (64-bits)
    rnd = Random.new()
    n1 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)   # Need to convert to ints for bytes... otherwise JSON can't serialize
    data = {}
    data['nonce'] = n1
    data['requester'] = 1   # Requester is 1, since it is Alice
    data['requesting'] = 2  # Requesting is 2, since Alice is requesting Bob (2)
    data['encrypted_nonce'] = int.from_bytes(encrypt_nonce, byteorder=sys.byteorder)
    json_data = json.dumps(data)
    print('Sending to KDC:', json_data)
    s_kdc.sendall(json_data.encode('utf-8'))

    # Receive value from KDC
    data_from_kdc = s_kdc.recv(MESSAGE_SIZE)
    print('Encrypted text received from KDC:', data_from_kdc)
    cipher_alice = DES3.new(ka, DES3.MODE_CBC, iv)
    decrypted_text = cipher_alice.decrypt(data_from_kdc)
    json_data = json.loads(data_from_kdc.rstrip())
    print('Data received from KDC:', json_data)



if __name__ == "__main__":
    main()