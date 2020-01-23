from string import ascii_letters
import secrets
import sys

def main():
    ####################
    #                  #
    #       PART 2     #
    #                  #
    ####################
    char_input = input('8CHAR INPUT: ')
    encrypt_translations, decrypt_translations = create_substitution_tables()

    key = 'Ee4CQUOc'
    number_of_rounds = 16

    encrypted_str = encrypt(key, encrypt_translations, char_input, number_of_rounds)
    print('ENCRYPTED STR: ', encrypted_str)

    decrypted_str = decrypt(key, decrypt_translations, encrypted_str, number_of_rounds)
    print('DECRYPTED STR: ', decrypted_str)
    

# Encrypt the input using the key and translations
# passed in
def encrypt(key, translations, input, number_of_rounds):

    # First XOR the key with the input (need byte arrays to do this)
    input_byte_array = bytearray(input, encoding='utf8')
    key_byte_array = bytearray(key, encoding='utf8')
    encrypted_byte_array = bytearray(len(key_byte_array))

    for i in range(len(key_byte_array)):
        encrypted_byte_array[i] = input_byte_array[i] ^ key_byte_array[i]

    
    # We need to encrypt for a certain number of rounds
    for i in range(number_of_rounds):
        
        # First perform substutions on each character
        for j in range(len(encrypted_byte_array)):
            translation = translations[j][encrypted_byte_array[j]]
            encrypted_byte_array[j] = translation

        # Now circular shift left 1 (algo taken from https://www.geeksforgeeks.org/rotate-bits-of-an-integer/)
        byte_array_val = int.from_bytes(encrypted_byte_array, byteorder=sys.byteorder)
        new_val = ((byte_array_val << 1) | byte_array_val >> 63) & 0xFFFFFFFFFFFFFFFF
        encrypted_byte_array = bytearray(new_val.to_bytes(len(encrypted_byte_array), byteorder=sys.byteorder))

        print('Encrypted byte array after round', i + 1, ':', encrypted_byte_array)     

    return encrypted_byte_array     

# Decrypt the input using the key and translations
# passed in
def decrypt(key, translations, input, number_of_rounds):
    
    # We need to encrypt for a certain number of rounds
    for i in range(number_of_rounds):
        
        # First circular shift right 1(algo taken from https://www.geeksforgeeks.org/rotate-bits-of-an-integer/)
        byte_array_val = int.from_bytes(input, byteorder=sys.byteorder)
        new_val = (byte_array_val >> 1) | (byte_array_val << (63) & 0x8000000000000000) & 0xFFFFFFFFFFFFFFFF
        input = bytearray(new_val.to_bytes(len(input), byteorder=sys.byteorder))

        # Then perform substutions on each character
        for j in range(len(input)):
            translation = translations[j][input[j]]
            input[j] = translation

        print('Encrypted byte array after round', i + 1, ':', input)  

    # Last XOR the key with the input (need byte arrays to do this)
    key_byte_array = bytearray(key, encoding='utf8')

    for i in range(len(key_byte_array)):
        input[i] = input[i] ^ key_byte_array[i]

    return input

# Method used for creating the 8 substitution tables needed for each of the characters
def create_substitution_tables():
    encrypt_translations = []
    decrypt_translations = []

    # Need to create 8 translation tables
    for i in range(8):
        values = list(range(256))
        current_index = 0
        new_encrypt_table = {}
        new_decrypt_table = {}
        while (len(values) != 0):
            mapping1 = secrets.choice(values)
            new_encrypt_table[current_index] = mapping1
            new_decrypt_table[mapping1] = current_index
            current_index += 1
            values.remove(mapping1)

        encrypt_translations.append(new_encrypt_table)
        decrypt_translations.append(new_decrypt_table)

    return encrypt_translations, decrypt_translations

if __name__ == '__main__':
    main()