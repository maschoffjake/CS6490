#
# Create the Trudy client that is used to 

import socket
import sys
from Crypto import Random
from Crypto.Cipher import DES3
import base64

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

def main():

    # STEP 1
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    
    

if __name__ == "__main__":
    main()