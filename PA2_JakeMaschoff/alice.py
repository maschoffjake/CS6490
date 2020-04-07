#
#
#

import socket
import sys
import base64
import argparse
import numpy as np
import random
import datetime
from Crypto import Random

# Cryptography libraries used for generating certs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

# Using a base msg size of 1KB
MESSAGE_SIZE = 2048

# Alice's secret key!
ka = b'6CCD4EE1B2B37A8C'

# Fermat primes (used with RSA)
public_exponent_list = [3, 5, 17, 257, 65537]

# Key size
KEY_SIZE = 2048

# Flag for client to authenticate as well (by sending certificate)
send_cert = True
server_sending = True

# Intialization vector used for the CBC cipher
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def begin_handshake():

    # Store the cert after it is received and unencrypted nonce once it received
    cert_received = None
    nonce_received = None

    # Create the self signed certificate for Alice
    # Most code taken from https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    # First create the key (using RSA)
    key = rsa.generate_private_key(
        public_exponent=random.choice(public_exponent_list),
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    with open("key-alice-" + str(datetime.datetime.utcnow()) +  ".pem", "wb") as f:
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
        x509.NameAttribute(NameOID.COMMON_NAME, u"alice"),
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

    # Write the cert to disk
    with open("cert-alice-" + str(datetime.datetime.utcnow()) + ".pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # STEP 1 send client_hello
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))

    # Using the record format
    # Taken from https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html#anc2
    handshake_record_header= bytearray([0x16, 0x03, 0x00])      # Handshake record (0x16) and SSL v3 (ADD LENGTH AFTER KNOWING HOW LONG!)

    # Now create the handshake message
    handshake_msg = bytearray([0x01])                                               # Client hello
    handshake_msg.extend(bytearray((8).to_bytes(3, byteorder='big')))               # Length
    handshake_msg.extend(bytearray([0x03, 0x00]))                                   # Version number SSL v3
    handshake_msg.extend(bytearray([0x0]))                                          # length of session_id (absent so 0)
    handshake_msg.extend(bytearray([0x0,0x2]))                                      # length of cipher suite (just 2 since we are picking ciper, and length in octets)
    handshake_msg.extend(bytearray([0x00,0xB7]))                                    # Cipher to use TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
    handshake_msg.extend(bytearray([0x0]))                                          # No compression 
    
    # Add the length to the record header
    length = len(handshake_msg)
    client_hello_header = handshake_record_header + ((length).to_bytes(2, byteorder='big'))

    print('STEP 1 client hello:')
    print('HEADER:', client_hello_header)
    print('Client hello message:', handshake_msg)
    client_hello_msg = client_hello_header + handshake_msg
    print('Alice sent to Bob:', client_hello_msg)
    print('\n')
    s_bob.sendall(client_hello_msg)


    # STEP 2 receive server hello, cert, and request from Bob
    msg = s_bob.recv(MESSAGE_SIZE)
    print('STEP 2 server hello')
    print('Received from Bob:', msg)
    cert_received = process_handshake_msg(msg,key)
    print('\n')

    # STEP 3 send encrypted nonce and certificate (if requested)
    # Now create a ClientKeyExchange
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
    client_key_exchange_msg = bytearray([0x10])                                                      # Server key exchange type
    client_key_exchange_msg.extend(bytearray((len(ciphertext)).to_bytes(3, byteorder='big')))        # Length
    client_key_exchange_msg.extend(bytearray(ciphertext))                                            # Ciphertext
    length = len(client_key_exchange_msg) 

    # If we received a certificate request, send it to the server
    if send_cert:
        # Now create the certificate to add to the record
        cert_len = (len(cert.public_bytes(serialization.Encoding.PEM))).to_bytes(3, byteorder='big')
        client_certificate_msg = bytearray([0x0b])                                              # Certificate type
        client_certificate_msg.extend(bytearray(cert_len))                                      # Length
        client_certificate_msg.extend(bytearray(cert.public_bytes(serialization.Encoding.PEM))) # Certificate
        length += len(client_certificate_msg)

    # Add the length to the record header
    certificate_header = handshake_record_header + ((length).to_bytes(2, byteorder='big'))

    print('STEP 3 sending cert (if requested) and client key exchange:')
    print('HEADER:', certificate_header)
    print('Nonce created:', nonce)
    print('Encrypted nonce:', ciphertext)
    print('Client key exchange message:', handshake_msg)
    client_key_exchange_and_cert_msg = certificate_header + client_key_exchange_msg
    if send_cert:
        print('Client cert message:', client_certificate_msg)
        client_key_exchange_and_cert_msg += client_certificate_msg
    print('Alice sent to Bob:', client_key_exchange_and_cert_msg)
    print('\n')
    s_bob.sendall(client_key_exchange_and_cert_msg)

    # STEP 4 receive the encrypted nonce from the server and server done!
    encrypted_nonce_msg = s_bob.recv(MESSAGE_SIZE)
    print('STEP 4 receive encrypted nonce')
    print('Recieved from Bob:', encrypted_nonce_msg)
    nonce_received = process_handshake_msg(encrypted_nonce_msg, key)
    print('Decrypted nonce received:', nonce_received)
    print('\n')

    master_secret = bytes(a ^ b for a, b in zip(nonce, nonce_received))
    print('********************************************************************************************************************')
    print('Master secret created:', master_secret)
    print('********************************************************************************************************************')
    print('\n')

    # STEP 5 Receive MAC from server (keyed SHA-1 with SERVER appended)
    mac_msg = s_bob.recv(MESSAGE_SIZE)
    

#
#   Used to process an incoming message. Check the overall header and make sure to read each of 
#   the record messages contained within the header
#
def process_handshake_msg(msg,key):
    # Flags used for returning nonce and cert
    return_cert = False
    return_nonce = False
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
        if type_of_msg == 2:        # server hello
            print('Processing server hello type msg')
            service_hello_server(msg_to_proccess[4:])
        elif type_of_msg == 14:     # server done
            print('Server done sending messages!')
        elif type_of_msg == 13:     # certificate request
            print('Processing certificate request type msg')
            send_cert = True
        elif type_of_msg == 11:     # certificate
            print('Processing certificate type msg')
            cert_recv = process_certificate(msg_to_proccess[4:], length)
            return_cert = True
        elif type_of_msg == 14:     # server hello done
            print('Processing server hello done type msg')
            server_sending = False
        elif type_of_msg == 12:     # server key exchange
            print('Processing server key exchange')
            nonce_received = process_server_key_exchange(msg_to_proccess[4:], length, key)
            print('Received nonce (after unecnrypting):', nonce_received)
            return_nonce = True
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
    
    # Return values if received
    if return_cert:
        return cert_recv
    if return_nonce:
        return nonce_received

'''
        Used to process the encrypted nonce that is sent from the server
        Returns the plaintext from the encrypted nonce 
'''
def process_server_key_exchange(msg, length, key):
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
    No chosen cipher or chosen compression since none will be used. Session id should be 0
    2               version number
    1               length of session id
'''
def service_hello_server(msg):
    # Check to make sure the correct values are set
    version_number_payload = msg[0:2]
    if version_number_payload != b'\x03\x00':
        print('BAD! Wrong version number. Expecting SSL v3')
        exit(-1)

    session_id = msg[2]
    if session_id != 0x00:
            print('BAD! Unexpected session ID')
            exit(-1)

    # All checks went well! Received correct server_hello
    print('Correct server_hello received')

def main():

    # Begin the handshake phase with Bob
    begin_handshake()


if __name__ == "__main__":
    main()