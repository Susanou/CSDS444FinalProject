def shift_left(number, amount):  # number is a binary string
    for i in range(0, amount):
        number = number + number[i]
    return number[amount:]


def shift_right(number, amount):  # number is a binary string
    for i in range(amount):
        number = number[-1] + number
        number = number[0:len(number)-1]
    return number


def encrypt(message, B, N):
    output_bin = ''
    encodedBits = ''
    # get unicode values in binary for message. Make sure all are length 8
    for char in message:
        b = str(bin(ord(char)))
        b = b.replace('b', '')
        #print(b)
        b = b.zfill(8)
        output_bin += b
    bin_length = len(output_bin)
    #print(output_bin)

    # make length multiple of B sized blocks
    while len(output_bin) % B != 0:
        output_bin += '0'
    #print(output_bin)

    # perform circular bit shifts on blocks
    for x in range(1, int(len(output_bin)/B + 1)):
        z = output_bin[(x - 1) * B:x * B]
        if N > 0:
            z = shift_left(z, N)
        elif N < 0:
            z = shift_right(z, -N)
        encodedBits += z
    #print(encodedBits)

    cipher_text = ''
    # get hex values for these new shifted blocks
    for x in range(1, int(len(encodedBits)/8 + 1)):
        c = encodedBits[(x - 1) * 8:x * 8]
        # cipher_text += chr(int(c, 2))  # not all of these will be printable. Instead switch to just hex
        hex_val = hex(int(c, 2))
        cipher_text += hex_val[2:] + ' '
    # get last hex value for multiples not of 8
    if len(encodedBits) < 8:
        hex_val = hex(int(encodedBits, 2))
        cipher_text = hex_val[2:]
    elif len(encodedBits) % 8 > 0:
        hex_val = hex(int(encodedBits[-(len(encodedBits) % 8):], 2))
        cipher_text += hex_val[2:]

    return cipher_text


def decrypt(message, B, N):
    # N is switched for decryption
    N = -N
    # get binary values from hex string
    bin_values = [bin(int(x, 16)) for x in message.split()]
    encodedBits = ''
    # add bit values to a string
    for i in range(len(bin_values)-1):
        bits = bin_values[i]
        bits = bits[2:].zfill(8)
        encodedBits += bits
    # handle the last binary value separately for length considerations
    last = bin_values[-1]
    last = last[2:]
    # make encoded bit length multiple of B
    while (len(encodedBits) + len(last)) % B != 0:
        last = '0' + last
    #print(bin_values[-1])
    encodedBits += last
    #print(encodedBits)
    decodedBits = ''
    bin_length = len(encodedBits)
    #print(bin_length)

    # perform bit shifts on blocks. Add new blocks to decodedBit string
    for x in range(1, int(len(encodedBits)/B + 1)):
        z = encodedBits[(x - 1) * B:x * B]
        if N > 0:
            z = shift_left(z, N)
        elif N < 0:
            z = shift_right(z, -N)
        decodedBits += z

    #print(decodedBits)
    decoded_message = ''

    # get unicode characters for binary blocks
    for x in range(1, int(len(decodedBits) / 8 + 1)):
        # print((decoded_bin[(x - 1) * 8:x * 8], 2))
        decoded_message = decoded_message + chr(int(decodedBits[(x - 1) * 8:x * 8], 2))

    return decoded_message

'''
B = int(input('Choose block size: '))
N = int(input('Choose shift amount: '))

choice = input('Encrypt or Decrypt? E/D: ')
mess = input('Enter a message: ')

if choice == 'e' or choice == 'E':
    print('Message to be encoded:', mess)
    encoded_mess = encrypt(mess, B, N)
    print('Encoded message:', encoded_mess)
elif choice == 'd' or choice == 'D':
    print('Message to be decoded:', mess)
    decoded_mess = decrypt(mess, B, N)
    print('Decoded Message:', decoded_mess)
'''
