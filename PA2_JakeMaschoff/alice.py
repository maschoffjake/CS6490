#
#
#

import socket
import sys
from Crypto import Random
from Crypto.Cipher import DES3
import base64
import argparse

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

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
    rnd = Random.new()
    nb = rnd.read(8)
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    s_bob.send(msg)
    print('STEP 1 HANDSHAKE:')
    print('Alice sent to Bob:', msg)
    print('\n')
    
    #STEP 3
    # Create a nonce to send along with this message (64-bits)
    rnd = Random.new()
    n1 = int.from_bytes(rnd.read(8), byteorder=sys.byteorder)   # Need to convert to ints for bytes... otherwise JSON can't serialize
    data = {}
    data['nonce'] = n1
    data['requester'] = 1   # Requester is 1, since it is Alice
    data['requesting'] = 2  # Requesting is 2, since Alice is requesting Bob (2)

if __name__ == "__main__":
    main()