def main():
    ####################
    #                  #
    #       PART 1     #
    #                  #
    ####################
    key = input('KEY: ')
    # message = input('MESSAGE TO ENCRPY: ')
    message = 'This class is not hard at all.'
    state, x, y = rc4init(key, len(key))

    # Skip the first 512 iterations
    for i in range(512):
        byte, x, y = rc4step(state, x, y)
        # print(byte, x, y)

    ret_str = ''
    for c in message:
        byte, x, y = rc4step(state, x, y)
        print(byte)
        ret_str += str(ord(c) ^ byte)

    print(state)

    print('ENCRYPTED MESSAGE: ', ret_str)
    

# Intitialize the values used for for RC4
# Returns state array, x number, and y number
def rc4init(key, length):
    state = []
    for i in range(256):
        state.append(i)

    j = 0
    i = 0
    k = 0
    
    while (i < 256):
        t = state[i]
        k = k + ord(key[j]) + t
        state[i % 256] = state[k % 256]
        state[k % 256] = t

        # Next state values
        i += 1
        j = (j + 1) % length

    return state, 0, 0

def rc4step(state, x, y):
    x += 1
    y += state[x % 256]
    t = state[y % 256]
    state[y % 256] = state[x % 256]
    state[x % 256] = t
    return state[(state[x % 256] + state[y % 256]) % 256], x, y

if __name__ == '__main__':
    main()