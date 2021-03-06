#
# Create the Alice node that is used in the Expanded Needham Schroder protocol

import socket
import sys
import json
from Crypto import Random
from Crypto.Cipher import DES3
import base64
import argparse

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001
PORT_KDC = 5000

# Using a base msg size of 1KB
MESSAGE_SIZE = 1024

# Alice's secret key!
ka = b'6CCD4EE1B2B37A8C'

# Intialization vector used for the CBC cipher
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

def main():

    # Check to see if we should use ECB or CBC
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--ecb", action="store_true",
                    help="use ECB secret key function instead of default (CBC)")
    args = parser.parse_args()
    cbc = not args.ecb

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
    print('Alice received encrypted nonce from Bob:', encrypt_nonce)
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

    # Create the correct cipher
    if cbc:
        cipher_alice = DES3.new(ka, DES3.MODE_CBC, iv)
    else:
        cipher_alice = DES3.new(ka, DES3.MODE_ECB)
    
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
    kab = base64.decodebytes(json_data['kab'].encode('ascii'))
    if cbc:
        kab_cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        kab_cipher = DES3.new(kab, DES3.MODE_ECB)
    encrypted_n2 = kab_cipher.encrypt(n2)
    data['encrypted_n2'] = int.from_bytes(encrypted_n2, byteorder=sys.byteorder)
    send_json = json.dumps(data)
    print('STEP 5:')
    print('Received Kab:', kab)
    print('Created N2 nonce:', int.from_bytes(n2, byteorder=sys.byteorder))
    print('Sending to Bob:', send_json)
    print('\n')
    s_bob.sendall(send_json.encode('utf-8'))

    # STEP 6
    print('STEP 6:')
    data = s_bob.recv(MESSAGE_SIZE)
    print('Received encrypted data from Bob:', data)
    # Decrypt the data
    if cbc:
        cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kab, DES3.MODE_ECB)
    decrypted_data = cipher.decrypt(data).decode().rstrip('0')
    print('Decrypted data:', decrypted_data)
    json_data = json.loads(decrypted_data)
    # Check the nonce n2
    n2_dec = json_data['dec_n2']
    n2 = int.from_bytes(n2, byteorder=sys.byteorder)
    if (n2 - 1 == n2_dec):
        print('Got back correct N2!')
    else:
        print('Got back wrong N2. Tampered with. Exiting')
        exit()


    # STEP 7
    print('STEP 7:')
    n3_alpha = json_data['n3'] - 1
    print('Sending back N3 - 1:', n3_alpha)
    data = {}
    data['dec_n3'] = n3_alpha
    data_to_send = json.dumps(data)
    while (len(data_to_send) % 8 != 0):
        data_to_send += '0'
    # Encrypt the JSON
    encrypted_data_to_send = cipher.encrypt(data_to_send)
    print('Sending to bob encrypted data:', encrypted_data_to_send)
    s_bob.sendall(encrypted_data_to_send)
    print('DONE! Using shared key:', kab)

if __name__ == "__main__":
    main()