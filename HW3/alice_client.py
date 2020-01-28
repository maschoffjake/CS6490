#
# File used to perform the diffie hellman 
# handshake between two entities
#
# Also uses the expo.py file to perform the 
# modular exponnenation of large numbers
#

from expo import expo

def main():
    print('ENTER ALL VALUES AS INTEGERS')
    m = int(input('m: '))
    d = int(input('d: '))
    n = int(input('n: '))

    # ALICIES SECRET!!! #
    sa = 168738398951287021945443883386595563887358474577763765921113335741943539892079087759211939702224794512107293492337353174782738849420938332474484719183

    exponent_value = expo(m, d, n)

if __name__ == "__main__":
    main()