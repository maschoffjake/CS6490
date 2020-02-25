#
# Create the Alice client that is used in the extended needham-schroeder protocol
#

import socket
import sys
import json
from Crypto import Random
from Crypto.Cipher import DES3
import base64

HOST = 'localhost'
PORT_BOB = 5001
PORT_KDC = 5000

MESSAGE_SIZE = 1024

ka = b'6CCD4EE1B2B37A8C'
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

def main():
    # STEP 1
    # First send to Bob a 1, tell him that Alice wants to communicate with them
    msg = bytes([1])
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    s_bob.send(msg)
    print('STEP 1:')
    print('Alice sent to Bob:', msg)
    print('\n')

    # STEP 2
    # Receive the nonce encrypted by Bob, and send it to the KDC
    encrypt_nonce = s_bob.recv(MESSAGE_SIZE)
    print('STEP 2:')
    print('Alice received from Bob:', encrypt_nonce)
    print('\n')
    s_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_kdc.connect((HOST, PORT_KDC))
    
    #STEP 3
    # Create a nonce to send along with this message (64-bits)
    rnd = Random.new()
    n1 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)   # Need to convert to ints for bytes... otherwise JSON can't serialize
    data = {}
    data['nonce'] = n1
    data['requester'] = 1   # Requester is 1, since it is Alice
    data['requesting'] = 2  # Requesting is 2, since Alice is requesting Bob (2)
    data['encrypted_nonce'] = int.from_bytes(encrypt_nonce, byteorder=sys.byteorder)
    json_data = json.dumps(data)
    print('STEP 3:')
    print('Sending to KDC:', json_data)
    print('\n')
    s_kdc.sendall(json_data.encode('utf-8'))

    # STEP 4
    # Receive value from KDC
    data_from_kdc = s_kdc.recv(MESSAGE_SIZE)
    print('STEP 4:')
    print('Encrypted text received from KDC:', data_from_kdc)
    cipher_alice = DES3.new(ka, DES3.MODE_CBC, iv)
    decrypted_text = cipher_alice.decrypt(data_from_kdc)
    json_data = json.loads(decrypted_text.rstrip())
    print('Decrypted data received from KDC:', json_data)
    if n1 == json_data['nonce']:
        print('Received correct nonce!')
    else:
        print('Received incorrect nonce! NOT KDC! Abort.')
        exit()
    print('\n')

    # STEP 5
    data = {}
    data['ticket'] = json_data['ticket']
    # Create a new nonce, encrypt it using kab
    n2 = rnd.read(8)
    kab = json_data['kab'].encode('utf-8')
    kab_cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    encrypted_n2 = kab_cipher.encrypt(n2)
    data['encrypted_n2'] = int.from_bytes(encrypted_n2, byteorder=sys.byteorder)
    send_json = json.dumps(data)
    print('STEP 5:')
    print('Created N2 nonce:', int.from_bytes(n2, byteorder=sys.byteorder))
    print('Sending to Bob:', send_json)
    print('\n')
    s_bob.sendall(send_json.encode('utf-8'))

    # STEP 6
    data = s_bob.recv(MESSAGE_SIZE)
    print('Received encrypted data from Bob:', recv)


if __name__ == "__main__":
    main()