'''
        Client node used in an SSL transaction (Alice)
        Starts communication with the server node (Bob)
        Performs a handshake, and then asks for a file that is contained on the server,
        which the server will then send over the keys made through the SSL handshake
'''

# Sys libraries
import socket
import sys
import numpy as np
import random
import datetime

# Cryptography libraries used for generating certs, padding, AES, KDF, HMAC, etc
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hmac
from cryptography import x509
from cryptography.hazmat.primitives import hashes, padding as pad
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Crypto import Random


# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

# Using a base msg size of 32KB
MESSAGE_SIZE = 32 * 1024

# Salt shared between the 2 nodes, assuming it is shared!
shared_salt = b'\xe4\xebb\x94\xf3K\xe1\x80ND@\x08\xe97\\\x119\xaaK\xbfrn\xb9\tA\x13Q\xd5o\x85\xfa\x03\x10y@+(Q\xcb\x00+\xa2\xb8\xe4\x0f\xf2\x1b\x89\xe2\xcb\x03}\x8d\xfefv\x1a6\x0f\xad3-\x17\xdb2\x1c\xadx\xd64\xd7\xca.\xee\xa8\xab@*\xfdO\x0b\x9b\xc7\x0c\xbc\xa8!jN\xea?%\xfb\xde\xa8\xf5\x97\xcb\x16\x07\xd2\xc04*\x99\x8dA0\x15\x0c_\xe8\x99\xa2y\x93\xa8\t9<o\xdb\x94R\xc3~&\xd9'

# Fermat primes (used with RSA)
public_exponent_list = [3, 5, 17, 257, 65537]

# Key size
KEY_SIZE = 2048

# File to request from server
requested_file = b'frankenstein_book.txt'

# Flag for client to authenticate as well (by sending certificate)
send_cert = True
server_sending = True

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
    cert_received = process_handshake_msg(msg)
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

    # Now create a MAC of all the messages that have been sent and SERVER and CLIENT appended (keyed SHA-1)
    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(client_hello_msg)
    digest.update(msg)
    digest.update(client_key_exchange_and_cert_msg)
    digest.update(encrypted_nonce_msg)
    digest.update(master_secret)

    # Create a copy for now, so we can check CLIENT MAC
    digest_client = digest.copy()
    digest_client.update(b'CLIENT')
    mac_client = digest_client.finalize()

    # Finish digest to send by appending SERVER
    digest.update(b'SERVER')
    mac_server = digest.finalize()

    # STEP 5 Receive MAC from server (keyed SHA-1 with SERVER appended)
    mac_msg = s_bob.recv(MESSAGE_SIZE)
    print('STEP 5 receive MAC from server')
    print('Received MAC from bob:', mac_msg)
    process_handshake_msg(mac_msg, expected_mac=mac_server)
    print('\n')

    # STEP 6 send client MAC to server
    # Now create a certificate verify message
    mac_length = len(mac_server)
    client_mac_msg = bytearray([0x0f])                                                              # Certificate verify msg
    client_mac_msg.extend(bytearray((mac_length).to_bytes(3, byteorder='big')))                     # Length
    client_mac_msg.extend(bytearray(mac_client))                                                    # MAC value

    # Add the length to the record header
    length = len(client_mac_msg)
    handshake_header_total = handshake_record_header + (length).to_bytes(2, byteorder='big')

    total_mac_msg = handshake_header_total + client_mac_msg
    print('STEP 6 send client MAC')
    print('HEADER:', handshake_header_total)
    print('MAC:', mac_client)
    print('Sending to Bob:', total_mac_msg)
    s_bob.sendall(total_mac_msg)

    # DONE WITH HANDSHAKE! Create keys
    print('\n')
    print('***** DONE WITH HANDSHAKE! AUTHENTICATED *****')
    print('\n')

    # Create keys... using https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=160,         # need to generate 4-keys (32-bytes each)
        salt=shared_salt,
        iterations=1000000, # recommended is 1mil
        backend=default_backend()
    )
    keys_bytes = kdf.derive(master_secret)

    # Create the keys associated with client
    keys = {
        'encrypt': keys_bytes[0:32],
        'decrypt': keys_bytes[32:64],
        'auth_send': keys_bytes[64:96],
        'auth_recv': keys_bytes[96:128],
        'iv': keys_bytes[128:]
    }

    return keys, s_bob

#
#   Used to process an incoming message. Check the overall header and make sure to read each of 
#   the record messages contained within the header
#
def process_handshake_msg(msg,key=None, expected_mac=None):
    # Flags used for returning nonce and cert
    return_cert = False
    return_nonce = False
    # Check to make sure the headers are correct
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

'''
        Function to be used for when the ssl transaction has entered data transfer phase
        Pass in the 4 keys to be used for the data transfer phase plus IV
'''
def handle_data_transfer(keys, s_bob):

    # Create default header
    data_transfer_record_header = bytearray([0x17, 0x03, 0x00])      # Application data record (0x17) and SSL v3 (ADD LENGTH AFTER KNOWING HOW LONG!)

    # Padder and unpadder
    padder = pad.PKCS7(128).padder()
    unpadder = pad.PKCS7(128).unpadder()

    # Create ciphers
    cipher_encrypt = Cipher(algorithms.AES(keys['encrypt']), modes.CBC(keys['iv'][:16]), backend=default_backend())
    cipher_decrypt = Cipher(algorithms.AES(keys['decrypt']), modes.CBC(keys['iv'][16:]), backend=default_backend())

    # Create HMACs
    hmac_send = hmac.HMAC(keys['auth_send'], hashes.SHA256(), backend=default_backend())
    hmac_recv = hmac.HMAC(keys['auth_recv'], hashes.SHA256(), backend=default_backend())

    # Sending first sequence
    sequence_num = 1
    record_data = requested_file
    length_of_record = len(record_data)
    total_record_header = data_transfer_record_header + (length_of_record).to_bytes(2, byteorder='big')

    # Calculate the HMAC
    hmac_send.update((sequence_num).to_bytes(1, byteorder='big'))
    hmac_send.update(total_record_header)
    hmac_send.update(record_data)
    hmac_val = hmac_send.finalize()

    # Pad and encrypt the record data and HMAC
    encryptor = cipher_encrypt.encryptor()
    msg_to_pad = record_data + hmac_val
    padded_data = padder.update(msg_to_pad) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    total_msg = total_record_header + ct
    print('Sending request for file', requested_file.decode())
    print('HMAC', hmac_val)
    print('Unecrypted msg:', padded_data)
    print('Encrypted msg:', ct)
    print('Total msg being sent:', total_msg)
    print('\n')
    s_bob.sendall(total_msg)

    print('Receiving file now:')
    # Now receive the file from the server!
    file_bytes = bytearray()

    # Begin processing messages
    while (True):
        # Wait until a message come sin
        msg = s_bob.recv(MESSAGE_SIZE)
        sequence_num += 1

        # Must use a new unpadder each time
        unpadder = pad.PKCS7(128).unpadder()

        # Check to make sure the headers are correct
        if msg[0] != 0x17:
            print('BAD! Record header is not application data type')

        version_number = msg[1:3]
        if version_number != b'\x03\x00':
                print('BAD! Wrong version number. Expecting SSL v3')
                exit(-1)

        length_of_data = int.from_bytes(msg[3:5], byteorder='big')
        # If no data is contained, done receiving the file
        if length_of_data == 0:
            print('Done receiving file!')
            break

        encrypted_vals = msg[5:]

        # Decrypt the values, unpad, grab the hmac and data
        encrypted_vals = msg[5:]
        decryptor = cipher_decrypt.decryptor()
        decrypted_val = decryptor.update(encrypted_vals) + decryptor.finalize()
        unpadded_data = unpadder.update(decrypted_val) + unpadder.finalize()
        file_data = unpadded_data[:length_of_data]
        hmac_val = unpadded_data[length_of_data:]
        print('Received encrypted file data (truncated):', file_data[:20])
        print('Received unencrypted file data (truncated):', file_data[:20])
        print('Received HMAC:', hmac_val)
        print('Verifying HMAC...')

        # Verify the data was not tampered with (add sequence number, record header, and record data)
        # Create a new one each time since thats how the library works
        hmac_recv = hmac.HMAC(keys['auth_recv'], hashes.SHA256(), backend=default_backend())
        hmac_recv.update((sequence_num).to_bytes(1, byteorder='big'))
        hmac_recv.update(msg[:5])
        hmac_recv.update(decrypted_val[:length_of_data])
        try:
            hmac_recv.verify(hmac_val)
            print('HMAC verification passed! Wasn\'t tampered with')
            print('Correctly received seq', sequence_num, '\n')
        except Exception:
            print('HMAC verification failed! Exiting')
            exit(-1)

        # Add file bytes since they were not tampered with
        file_bytes.extend(file_data)


    f = open(requested_file.decode().split('.')[0] + '_received.txt', 'w+b')
    f.write(file_bytes)
    f.close()

def main():

    # Begin the handshake phase with Bob, get the keys after the handshake is complete
    keys, s_bob = begin_handshake()

    # Once the handshake is complete, start data transfer
    handle_data_transfer(keys, s_bob)

if __name__ == "__main__":
    main()