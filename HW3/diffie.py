#
# File used to perform the diffie hellman 
# handshake between two entities
#
# Also uses the expo.py file to perform the 
# modular exponnenation of large numbers
#

from expo import expo

def main():
    m = input('m: ')
    d = input('d: ')
    n = input('n: ')

    exponent_value = expo(m, d, n)

if __name__ == "__main__":
    main()