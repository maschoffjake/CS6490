#
# File used for computing large
# modular exponentiations
# m: value
# d: exponent
# n: modulo
def expo(m, d, n):
    
    # Turn the exponent to binary and iterate over each bit starting at MSB
    bin_val = bin(d)
    value = 1

    for bit_index in range(2, len(bin_val)):
        curr_bit = bin_val[bit_index]

        # Square the value
        value = value * value
        value = value % n

        # If it's a 1, multiply by the base of the exponentiation
        if curr_bit == '1':
            value = value * m
            value = value % n

    return value
