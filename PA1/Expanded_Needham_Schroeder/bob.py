#
# Bob node used in the Expanded  Needham 
#
import argparse
import socket
import sys
import threading
import os
import json
import base64
from Crypto.Cipher import DES3
from Crypto import Random

HOST = 'localhost'
PORT = 5001

kb = b'DC8FA9EE9BA7FTTA'
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

MESSAGE_SIZE = 1024

def handle_auth(conn, address, cbc):
    recv = conn.recv(MESSAGE_SIZE)
    print('STEP 1')
    print('Received from Alice:', recv)
    print('\n')
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
    msg = cipher.encrypt(nb)
    conn.sendall(msg)
    print('STEP 2')
    print('Unencrypted nonce value:', nb)
    print('Encrypted Bob sent to Alice:', msg)
    print('\n')

    print('STEP 5')
    recv = conn.recv(MESSAGE_SIZE)
    json_data = json.loads(recv.decode('utf-8'))
    ticket_encrypted = json_data['ticket']
    nonce_n2 = json_data['encrypted_n2'].to_bytes(8, byteorder=sys.byteorder)
    ticket_decoded = base64.decodebytes(ticket_encrypted.encode('ascii'))
    print('Received from Alice:', json_data)
    ticket_decrypted = cipher_2.decrypt(ticket_decoded).decode().rstrip('0')
    json_data = json.loads(ticket_decrypted)
    print('Decrpyted ticket:', json_data)
    kab = json_data['kab'].encode('utf-8')

    # Check to make sure the nb received is still the one that was originally sent out
    encrypted_nb_received = json_data['nb'].to_bytes(8, byteorder=sys.byteorder)
    print('Encrypted nonce Nb:', encrypted_nb_received)
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher = DES3.new(kb, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kb, DES3.MODE_ECB)
    decrypted_nb_received = cipher.decrypt(encrypted_nb_received)
    print('Decrypted nonce Nb:', decrypted_nb_received)
    if (nb == decrypted_nb_received):
        print('Got back correct NB!')
    else:
        print('Got back wrong NB. Must\'ve been tampered with. Exiting')
        exit()
    print('\n')

    print('STEP 6:')
     # Decrypt the nonce using the key now
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher_3 = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher_3 = DES3.new(kab, DES3.MODE_ECB)
    print('N2 encrypted:', nonce_n2)
    decrypted_nonce_2 = int.from_bytes(cipher_3.decrypt(nonce_n2), byteorder=sys.byteorder)
    print('N2 decrypted:', decrypted_nonce_2)
    decrypted_nonce_2_alpha = decrypted_nonce_2 - 1
    print('N2 - 1:', decrypted_nonce_2_alpha)
    n3 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)
    print('Created N3:', n3)
    data = {}
    data['dec_n2'] = decrypted_nonce_2_alpha
    data['n3'] = n3
    data_to_send = json.dumps(data)
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kab, DES3.MODE_ECB)
    encrypted_data_to_send = cipher.encrypt(data_to_send)
    print('Sending encrypted data to Alice:', encrypted_data_to_send)
    conn.sendall(encrypted_data_to_send)


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