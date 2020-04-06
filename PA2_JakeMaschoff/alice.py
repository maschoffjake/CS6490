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

# Cryptography libraries used for generating certs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

# Using a base msg size of 1KB
MESSAGE_SIZE = 1024

# Alice's secret key!
ka = b'6CCD4EE1B2B37A8C'

# Fermat primes
public_exponent_list = [3, 5, 17, 257, 65537]

# Key size
KEY_SIZE = 2048

# Intialization vector used for the CBC cipher
iv = b'\x81\xde\xa6\xf3u\x9d\x11\xdd'

'''
Byte   0       = SSL record type = 22 (SSL3_RT_HANDSHAKE)
Bytes 1-2      = SSL version (major/minor)
Bytes 3-4      = Length of data in the record (excluding the header itself).
Byte   5       = Handshake type
Bytes 6-8      = Length of data to follow in this record
Bytes 9-n      = Command-specific data   
'''

# Function used to start the KDC server
# Once a connection is made, it creates a new thread
# and passes it off to a new function (handle_kdc)
def begin_handshake():

    # Create the self signed certificate for Alice
    # Most code taken from https://cryptography.io/en/latest/x509/tutorial/#creating-a-self-signed-certificate
    # First create the key (using RSA)
    key = rsa.generate_private_key(
        public_exponent=random.choice(public_exponent_list),
        key_size=KEY_SIZE,
        backend=default_backend()
    )

    with open("key-" + str(datetime.datetime.utcnow()) +  ".pem", "wb") as f:
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
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
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
    with open("cert-" + str(datetime.datetime.utcnow()) + ".pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # STEP 1
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))

    # Using the record format
    # Taken from https://www.cisco.com/c/en/us/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html#anc2
    rec_type = np.uint8(0x16)           # 22 (handshake)
    rec_version = np.uint16(0x0300)     # 0x0300 to indicate SSL version 3
    handshake_type = np.uint8(0x01)     # Client hello
    data = {

    }


    print('STEP 1 HANDSHAKE:')
    print('Alice sent to Bob:', msg)
    print('\n')


def main():

    # Check to see if we should use ECB or CBC
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--ecb", action="store_true",
                    help="use ECB secret key function instead of default (CBC)")
    args = parser.parse_args()
    cbc = not args.ecb

    # Begin the handshake phase with Bob
    begin_handshake()


    
    #STEP 3
    # Create a nonce to send along with this message (64-bits)
    rnd = Random.new()
    n1 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)   # Need to convert to ints for bytes otherwise JSON can't serialize
    data = {}
    data['nonce'] = n1
    data['requester'] = 1   # Requester is 1, since it is Alice
    data['requesting'] = 2  # Requesting is 2, since Alice is requesting Bob (2)

if __name__ == "__main__":
    main()