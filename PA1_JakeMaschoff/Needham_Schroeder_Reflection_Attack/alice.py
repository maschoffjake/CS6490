#
# Create the Alice client that is used in the Needham-Schroeder protocol
#

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
    if cbc:
        print('CBC!')
    else:
        print('ECB!')

    # STEP 1
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    s_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_kdc.connect((HOST, PORT_KDC))

    # Create a nonce to send along with this message (64-bits)
    rnd = Random.new()
    n1 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)   # Need to convert to ints for bytes... otherwise JSON can't serialize
    data = {}
    data['nonce'] = n1
    data['requester'] = 1   # Requester is 1, since it is Alice
    data['requesting'] = 2  # Requesting is 2, since Alice is requesting Bob (2)
    json_data = json.dumps(data)
    print('STEP 1:')
    print('Sending to KDC:', json_data)
    print('\n')
    s_kdc.sendall(json_data.encode('utf-8'))

    # STEP 2
    # Receive value from KDC
    data_from_kdc = s_kdc.recv(MESSAGE_SIZE)
    print('STEP 2:')
    print('Encrypted text received from KDC:', data_from_kdc)

    # Create the correct cipher
    if cbc:
        cipher_alice = DES3.new(ka, DES3.MODE_CBC, iv)
    else:
        cipher_alice = DES3.new(ka, DES3.MODE_ECB)
    
    decrypted_text = cipher_alice.decrypt(data_from_kdc)
    print(decrypted_text)
    json_data = json.loads(decrypted_text.rstrip())
    print('Decrypted data received from KDC:', json_data)
    if n1 == json_data['nonce']:
        print('Received correct nonce!')
    else:
        print('Received incorrect nonce! NOT KDC! Abort.')
        exit()
    print('\n')

    # STEP 3
    # CANT USE JSON HERE! In order to execute the reflection attack
    # Need to now send only as bytes
    ticket = json_data['ticket'].encode('ascii')
    # Create a new nonce, encrypt it using kab
    n2 = rnd.read(8)
    kab = base64.decodebytes(json_data['kab'].encode('ascii'))
    if cbc:
        kab_cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        kab_cipher = DES3.new(kab, DES3.MODE_ECB)
    encrypted_n2 = kab_cipher.encrypt(n2)
    send_bytes = b''.join([ticket, encrypted_n2])
    print('STEP 3:')
    print('Created N2 nonce:', int.from_bytes(n2, byteorder=sys.byteorder))
    print('Sending to Bob:', send_bytes)
    print('\n')
    s_bob.sendall(send_bytes)

    # STEP 4
    # CANT USE JSON HERE! In order to execute the reflection attack
    print('STEP 4:')
    data = s_bob.recv(MESSAGE_SIZE)
    print('Received encrypted data from Bob:', data)
    # Decrypt the data
    if cbc:
        cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kab, DES3.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    print('Decrypted data:', decrypted_data)
    # Check the nonce n2
    n2_dec = decrypted_data[0:8]
    n3_bytes = decrypted_data[8:]
    print('N2 - 1:', n2_dec)
    print('N3:', n3_bytes)
    n2 = int.from_bytes(n2, byteorder=sys.byteorder)
    n2_dec = int.from_bytes(n2_dec, byteorder=sys.byteorder)
    if (n2 - 1 == n2_dec):
        print('Got back correct N2!')
    else:
        print('Got back wrong N2. Tampered with. Exiting')
        exit()
    print('\n')


    # STEP 5
    print('STEP 5:')
    n3 = int.from_bytes(n3_bytes, byteorder=sys.byteorder)
    n3_alpha = n3 - 1
    n3_alpha = n3_alpha.to_bytes(8, byteorder=sys.byteorder)
    print('Created N3 - 1:', n3_alpha)
    data_to_send = n3_alpha
    # Encrypt the bytes
    encrypted_data_to_send = cipher.encrypt(data_to_send)
    print('Sending to bob encrypted data:', encrypted_data_to_send)
    s_bob.sendall(encrypted_data_to_send)
    print('DONE! Using shared key:', kab)
    
    

if __name__ == "__main__":
    main()