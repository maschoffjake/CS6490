#
# Bob node used in the Expanded Needham Schroder protocol
#
import argparse
import socket
import sys
import threading
import base64
import datetime
import random
from Crypto import Random

# Cryptography libraries used for generating certs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac, padding as pad
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = 'localhost'
PORT = 5001

# Fermat primes (used with RSA)
public_exponent_list = [3, 5, 17, 257, 65537]

# Key size for RSA
KEY_SIZE = 2048

# Salt shared between the 2 nodes, assuming it is shared!
shared_salt = b'\xe4\xebb\x94\xf3K\xe1\x80ND@\x08\xe97\\\x119\xaaK\xbfrn\xb9\tA\x13Q\xd5o\x85\xfa\x03\x10y@+(Q\xcb\x00+\xa2\xb8\xe4\x0f\xf2\x1b\x89\xe2\xcb\x03}\x8d\xfefv\x1a6\x0f\xad3-\x17\xdb2\x1c\xadx\xd64\xd7\xca.\xee\xa8\xab@*\xfdO\x0b\x9b\xc7\x0c\xbc\xa8!jN\xea?%\xfb\xde\xa8\xf5\x97\xcb\x16\x07\xd2\xc04*\x99\x8dA0\x15\x0c_\xe8\x99\xa2y\x93\xa8\t9<o\xdb\x94R\xc3~&\xd9'

# Message blocks that are being sent between the nodes (32KB)
MESSAGE_SIZE = 32 * 1024

# Function used to pass threads off to when new connections are made with bob
# Handles all of the messages in the ENS protocol for a new connection
def handle_handshake(conn, address, cbc):

    # Cert received from Alice (since we are requesting it) and nonce received from Alice (unencrypted)
    cert_received = None
    nonce_received = None

    # Most code taken from https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    # First create the key (using RSA)
    key = rsa.generate_private_key(
        public_exponent=random.choice(public_exponent_list),
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    with open("key-bob-" + str(datetime.datetime.utcnow()) +  ".pem", "wb") as f:
     f.write(key.private_bytes(
         encoding=serialization.Encoding.PEM,
         format=serialization.PrivateFormat.TraditionalOpenSSL,
         encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
     ))

    # Create the cert
    # Various details about who we are. For a self-signed certificate the
    # subject and issuer are always the same.
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Utah"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Park City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of Utah"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"bob"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        # Can't use this cert until after it has been made
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Valid for 1 day
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    # Sign this cert with our RSA key we generated (self-signed)
    ).sign(key, hashes.SHA256(), default_backend())

    # STEP 1 client hello
    client_hello_msg = conn.recv(MESSAGE_SIZE)
    print('STEP 1 receive client_hello')
    print('Received from Alice:', client_hello_msg)
    process_handshake_msg(client_hello_msg)
    print('Correct client_hello received')
    print('\n')

    # STEP 2 sending server hello
    # Using the record format
    # Taken from https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html#anc2
    handshake_record_header= bytearray([0x16, 0x03, 0x00])                              # Handshake record (0x16) and SSL v3 (ADD LENGTH AFTER KNOWING HOW LONG!)

    # Now create the server hello message
    server_hello_msg = bytearray([0x02])                                                # Server hello type
    server_hello_msg.extend(bytearray((3).to_bytes(3, byteorder='big')))                # Length
    server_hello_msg.extend(bytearray([0x03, 0x00]))                                    # Version number SSL v3
    server_hello_msg.extend(bytearray([0x0]))                                           # length of session_id (absent so 0)

    # Now create the certificate to add to the record
    cert_len = (len(cert.public_bytes(serialization.Encoding.PEM))).to_bytes(3, byteorder='big')
    server_certificate_msg = bytearray([0x0b])                                              # Certificate type
    server_certificate_msg.extend(bytearray(cert_len))                                      # Length
    server_certificate_msg.extend(bytearray(cert.public_bytes(serialization.Encoding.PEM))) # Certificate

    # Now create the certificate request
    certificate_request_msg = bytearray([0x0d])                                         # Certificate request type
    certificate_request_msg.extend(bytearray((0).to_bytes(3, byteorder='big')))         # Length


    # Add the length to the record header
    length = len(server_hello_msg) + len(server_certificate_msg) + len(certificate_request_msg)
    handshake_header_total = handshake_record_header + (length).to_bytes(2, byteorder='big')            

    total_msg = handshake_header_total + server_hello_msg + server_certificate_msg + certificate_request_msg 
    conn.sendall(total_msg)
    print('STEP 2 send server_hello, certificate, and certificate request')
    print('HEADER:', handshake_header_total)
    print('Server hello msg:', server_hello_msg)
    print('Server certificate msg:', server_certificate_msg)
    print('Certificate request msg:', certificate_request_msg)
    print('Sent:', total_msg)
    print('\n')

    # STEP 3, await certificate, since we sent a request
    client_msg = conn.recv(MESSAGE_SIZE)
    print('STEP 3 receive certificate and client key exchange (encrypted nonce)')
    print('Received from Alice:', client_msg)
    cert_received, nonce_received = process_handshake_msg(client_msg, key)
    print('\n')

    # STEP 4 send back a ServerKeyExchange using the cert we received and a ServerDone since we no longer need to send anything for the handshake
    # Now create a ServerKeyExchange
    rnd = Random.new()
    nonce = rnd.read(32)
    ciphertext = cert_received.public_key().encrypt(
        nonce,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    server_key_exchange_msg = bytearray([0x0c])                                                      # Server key exchange type
    server_key_exchange_msg.extend(bytearray((len(ciphertext)).to_bytes(3, byteorder='big')))        # Length
    server_key_exchange_msg.extend(bytearray(ciphertext))                                            # Ciphertext

    # Add the length to the record header
    length = len(server_key_exchange_msg)
    handshake_header_total = handshake_record_header + (length).to_bytes(2, byteorder='big')
    
    print('STEP 4 send server key exchange and serer done msg')
    print('HEADER:', handshake_header_total)
    print('Nonce created:', nonce)
    print('Encrypted nonce:', ciphertext)
    print('Server key exchange msg:', server_key_exchange_msg)
    total_server_key_exchange_and_done_msg = handshake_header_total + server_key_exchange_msg 
    print('Sending to Alice:', total_server_key_exchange_and_done_msg)
    conn.sendall(total_server_key_exchange_and_done_msg)
    print('\n')

    master_secret = bytes(a ^ b for a, b in zip(nonce, nonce_received))
    print('********************************************************************************************************************')
    print('Master secret created:', master_secret)
    print('********************************************************************************************************************\n')

    # Now create a MAC of all the messages that have been sent and SERVER and CLIENT appended (keyed SHA-1)
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(client_hello_msg)
    digest.update(total_msg)
    digest.update(client_msg)
    digest.update(total_server_key_exchange_and_done_msg)
    digest.update(master_secret)

    # Create a copy for now, so we can check CLIENT MAC
    digest_client = digest.copy()
    digest_client.update(b'CLIENT')
    mac_client = digest_client.finalize()

    # Finish digest to send by appending SERVER
    digest.update(b'SERVER')
    mac_server = digest.finalize()

    # Now create a certificate verify message
    mac_length = len(mac_server)
    server_mac_msg = bytearray([0x0f])                                                              # Certificate verify msg
    server_mac_msg.extend(bytearray((mac_length).to_bytes(3, byteorder='big')))                     # Length
    server_mac_msg.extend(bytearray(mac_server))                                                    # MAC value

    # Now create a ServerDone message
    server_done_msg = bytearray([0x0e])                                                             # Server hello done type
    server_done_msg.extend(bytearray((0).to_bytes(3, byteorder='big')))                             # Length

    # Add the length to the record header
    length = len(server_mac_msg)+ len(server_done_msg)
    handshake_header_total = handshake_record_header + (length).to_bytes(2, byteorder='big')

    # Send the MAC and server done since server is done sending messages
    total_mac_msg = handshake_header_total + server_mac_msg + server_done_msg
    print('STEP 5 Sending MAC hash using keyed SHA-1 of previous messages')
    print('HEADER:', handshake_header_total)
    print('MAC:', mac_server)
    print('Server done msg:', server_done_msg)
    print('Sending to Alice:', total_mac_msg)
    conn.sendall(total_mac_msg)

    # STEP 6 receive client MAC, check it
    clientmac_msg = conn.recv(MESSAGE_SIZE)
    process_handshake_msg(clientmac_msg, expected_mac=mac_client)

    print('\n')

    # DONE WITH HANDSHAKE! Create keys
    print('\n')
    print('***** DONE WITH HANDSHAKE! AUTHENTICATED *****')
    print('\n')

    # Create keys... using https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=160,         # need to generate 4-keys (32-bytes each) and IV of 32-bytes
        salt=shared_salt,
        iterations=1000000, # recommended is 1mil
        backend=default_backend()
    )
    keys_bytes = kdf.derive(master_secret)

    # Create the keys associated with server
    keys = {
        'decrypt': keys_bytes[0:32],
        'encrypt': keys_bytes[32:64],
        'auth_recv': keys_bytes[64:96],
        'auth_send': keys_bytes[96:128],
        'iv': keys_bytes[128:]
    }

    # Now begin handling the data transfer phase
    handle_data_transfer(conn, keys)


'''
    First 5 bytes are header
    Expecting no session id, no compression algos, and only 1 cipher
    octet #         command type
    2               version #
    1               length_of session id
    2               length of cipher suites
    2               sequence of cipher suites
    1               compression list
'''
def service_client_hello(msg, length):
    try:

        version_number_msg = msg[0:2]
        if version_number_msg != b'\x03\x00':
            print('BAD! Wrong version number. Expecting SSL v3')
            exit(-1)  

        session_id = msg[2]
        if session_id != 0x00:
            print('BAD! Unexpected session ID')
            exit(-1)

        length_of_cipher_suite = msg[3:5]
        if length_of_cipher_suite != b'\x00\x02':
            print('BAD! Got more than 1 cipher, expecting just 1')
            exit(-1)

        cipher = msg[5:7]
        if cipher != b'\x00\xb7':
            print('BAD! Got unknown cipher')
            exit(-1) 

        compression = msg[7]
        if compression != 0x00:
            print('BAD! Unexpected compression')
            exit(-1)          

    except Exception as e:
        print('Unable to parse client_hello message')
        exit(-1)

#
#   Used to process an incoming message. Check the overall header and make sure to read each of 
#   the record messages contained within the header
#
def process_handshake_msg(msg, key=None, expected_mac=None):
    # Flag used for returning values for specific messages
    return_cert_and_nonce = False
    # Check to make sure the heads are correct
    if msg[0] != 0x16:
        print('BAD! Record header is not handshake type')

    version_number = msg[1:3]
    if version_number != b'\x03\x00':
            print('BAD! Wrong version number. Expecting SSL v3')
            exit(-1)

    total_record_length = int.from_bytes(msg[3:5], byteorder='big')

    msg_to_proccess = msg[5:]
    processing = True

    # Begin processing messages
    while (processing):
        type_of_msg = msg_to_proccess[0]
        length = int.from_bytes(msg_to_proccess[1:4], byteorder='big')
        # Check to see what message to process
        if type_of_msg == 1:        # client hello
            print('Processing client hello type msg')
            service_client_hello(msg_to_proccess[4:], length)
        elif type_of_msg == 11:     # certificate
            print('Processing certificate type msg')
            cert_recv = process_certificate(msg_to_proccess[4:], length)
            return_cert_and_nonce = True
        elif type_of_msg == 16:     # client key exchange
            print('Processing client key exchange')
            nonce_received = process_client_key_exchange(msg_to_proccess[4:], length, key=key)
            print('Received nonce (after unecnrypting):', nonce_received)
        elif type_of_msg == 15:     # certificate verify (hash verify)
            if msg_to_proccess[4:length+4] != expected_mac:
                print('BAD! Received incorrect MAC. Exiting')
                exit(-1)
            else:
                print('Received corect server MAC!')
        else:
            print('BAD! Unknown msg type of', type_of_msg,  'Exiting')
            exit(-1)
        
        # Take away for the header of this message and the message itself
        total_record_length -= 4
        total_record_length -= length

        # Read the next message (if there is one)
        msg_to_proccess = msg_to_proccess[length + 4:]

        # Done reading in messages after there is no more length
        if (total_record_length == 0):
            processing = False

        # Error check for invalid lengths
        if (total_record_length < 0):
            print('BAD! Received incorrect lengths. Unable to process entire record')
            exit(-1)

    if return_cert_and_nonce:
        return (cert_recv, nonce_received)
    return       

'''
        Used to process the encrypted nonce that is sent from the client
        Returns the plaintext from the encrypted nonce 
'''
def process_client_key_exchange(msg, length, key):
    print('Decrypying:', msg[:length])
    plaintext = key.decrypt(
     msg[:length],
     padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
        )
    )
    return plaintext

'''
        Load the certificate from the message, and save it as a global to be used in other messages
        Returns the cert
'''
def process_certificate(msg, length):
    try:
        cert_received = x509.load_pem_x509_certificate(msg[:length], default_backend())
        print('Loaded certificate correctly')
        return cert_received
    except Exception as e:
        print(str(e))
        exit(-1)

'''
        Function to be used for when the ssl transaction has entered data transfer phase
        Pass in the 4 keys to be used for the data transfer phase plus IV
        This function is expecting the client (Alice) to send a request for a file she would like to download
        This function will then supply the file encrypted
'''
def handle_data_transfer(conn, keys):
    
    # Create default header
    data_transfer_record_header = bytearray([0x17, 0x03, 0x00])      # Application data record (0x17) and SSL v3 (ADD LENGTH AFTER KNOWING HOW LONG!)

    # Padder and unpadder
    padder = pad.PKCS7(128).padder()
    unpadder = pad.PKCS7(128).unpadder()

    # Create ciphers
    cipher_decrypt = Cipher(algorithms.AES(keys['decrypt']), modes.CBC(keys['iv'][:16]), backend=default_backend())
    cipher_encrypt = Cipher(algorithms.AES(keys['encrypt']), modes.CBC(keys['iv'][16:]), backend=default_backend())

    # Create HMACs
    hmac_send = hmac.HMAC(keys['auth_send'], hashes.SHA256(), backend=default_backend())
    hmac_recv = hmac.HMAC(keys['auth_recv'], hashes.SHA256(), backend=default_backend())

    # Wait for the client to send what file it wants to download
    msg = conn.recv(MESSAGE_SIZE)
    print('Bob received request:', msg)

    # Check to make sure the headers are correct
    if msg[0] != 0x17:
        print('BAD! Record header is not application data type')

    version_number = msg[1:3]
    if version_number != b'\x03\x00':
            print('BAD! Wrong version number. Expecting SSL v3')
            exit(-1)

    length_of_data = int.from_bytes(msg[3:5], byteorder='big')

    # Decrypt the values, unpad, grab the hmac and data
    encrypted_vals = msg[5:]
    decryptor = cipher_decrypt.decryptor()
    decrypted_val = decryptor.update(encrypted_vals) + decryptor.finalize()
    unpadded_data = unpadder.update(decrypted_val) + unpadder.finalize()
    filename = unpadded_data[:length_of_data].decode()
    hmac_val = unpadded_data[length_of_data:]
    print('Received filename:', filename)
    print('Received HMAC:', hmac_val)
    print('Verifying HMAC...')

    # Start sequence number to 1
    sequence_num = b'1'

    # Verify the data was not tampered with (add sequence number, record header, and record data)
    hmac_recv.update(sequence_num)
    hmac_recv.update(msg[:5])
    hmac_recv.update(decrypted_val[:length_of_data])
    try:
        hmac_recv.verify(hmac_val)
        print('HMAC verification passed! Wasn\'t tampered with')
    except Exception:
        print('HMAC verification failed! Exiting')
        exit(-1)

    # How much data you should send with each packet at max (2^14)
    SSL_data_chunk_size = 16384
    # Going to transfer a frankenstein book
    with open(filename, 'r') as f:
        data = f.read(SSL_data_chunk_size)
        while data:
            # print(data)
            data = f.read(SSL_data_chunk_size)

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def start_server(cbc=False):
    print('Bob is listening')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    while True:
        (conn, address) = s.accept()
        t = threading.Thread(target=handle_handshake, args=(conn, address, cbc))
        t.daemon = False
        t.start()

def main():

    # Start the server
    start_server(True)

if __name__ == '__main__':
    main()