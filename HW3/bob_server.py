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

    # BOBS SECRET
    sb = 908072334292891247593799971527231563895031113003090396060420731983023976006275940225858794324743254334501672721055630648239479273437877559712395689954

    exponent_value = expo(m, d, n)

if __name__ == "__main__":
    main()