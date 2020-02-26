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
    # Set up cipher and random number generator
    rnd = Random.new() 
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher = DES3.new(kb, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kb, DES3.MODE_ECB)


    # STEP 3
    # NO LONGER USING JSON! Can't use with reflection attack
    print('STEP 3:')
    recv = conn.recv(MESSAGE_SIZE)
    print('Received from Alice:', recv)
    length_of_packet_ticket = len(recv) - 8 # Skip 8 bytes for the nonce
    ticket_encrypted = recv[0:length_of_packet_ticket]
    ticket_decoded = base64.decodebytes(ticket_encrypted)
    nonce_n2 = recv[length_of_packet_ticket:]
    print('Encrypted ticket received:', ticket_encrypted)
    print('Encrypted nonce N2 received:', nonce_n2)
    ticket_decrypted = json.loads(cipher.decrypt(ticket_decoded).decode().rstrip('0'))
    print('Decrpyted ticket:', ticket_decrypted)
    kab = base64.decodebytes(ticket_decrypted['kab'].encode('ascii'))
    print('\n')


    # STEP 4
    # NO LONGER USING JSON! Can't use with reflection attack
    print('STEP 4:')
     # Decrypt the nonce using the key now
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher_3 = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher_3 = DES3.new(kab, DES3.MODE_ECB)
    print('N2 encrypted:', nonce_n2)
    decrypted_nonce_2 = int.from_bytes(cipher_3.decrypt(nonce_n2), byteorder=sys.byteorder)
    print('N2 decrypted:', decrypted_nonce_2)
    decrypted_nonce_2_alpha = (decrypted_nonce_2 - 1).to_bytes(8, byteorder=sys.byteorder)
    print('N2 - 1:', decrypted_nonce_2_alpha)
    n3 = rnd.read(8)
    print('Created N3:', n3)
    data_to_send = b''.join([decrypted_nonce_2_alpha, n3])
    if cbc:
        # CBC requires an IV (intialization vector)
        cipher = DES3.new(kab, DES3.MODE_CBC, iv)
    else:
        cipher = DES3.new(kab, DES3.MODE_ECB)
    print('Decrypted values going to send:', data_to_send)
    encrypted_data_to_send = cipher.encrypt(data_to_send)
    print('Sending encrypted data to Alice:', encrypted_data_to_send)
    conn.sendall(encrypted_data_to_send)
    print('\n')

    # STEP 5
    print('STEP 5:')
    msg = conn.recv(MESSAGE_SIZE)
    print('Received from Alice:', msg)
    decrypted_msg = cipher.decrypt(msg)
    print('Decrypted message:', decrypted_msg)
    n3 = int.from_bytes(n3, byteorder=sys.byteorder)
    n3_dec = int.from_bytes(decrypted_msg, byteorder=sys.byteorder)
    print('N3:', n3)
    print('N3 - 1:', n3_dec)
    if (n3_dec != n3 - 1):
        print('Received back wrong N3. Tampered with. Exiting')
        exit()
    print('Received correct N3!')
    print('DONE. Using shared key with Alice:', kab)
    print('\n')

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