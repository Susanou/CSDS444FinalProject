lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def encrypt(message):
    cipher_text = ''
    unibits = ''
    for char in message:
        bin_char = bin(ord(char)).lstrip('0b')
        bin_char = bin_char.zfill(8)
        unibits += bin_char

    groups = [unibits[x:x+6] for x in range(0, len(unibits), 6)]

    if len(groups[-1]) < 6:
        groups[-1] += ('0'*(6-len(groups[-1][:])))

    for group in groups:
        cipher_text += lookup[int(group, 2)]

    while (len(cipher_text) ) % 4 != 0:
        cipher_text = cipher_text + '='

    return cipher_text


def decrypt(cipher_text):
    bit_str = ''
    decoded_text = ''

    for char in cipher_text:
        if char in lookup:
            bin_char = bin(lookup.find(char)).lstrip('0b')
            bin_char = bin_char.zfill(6)
            bit_str += bin_char

    while len(bit_str) % 8 != 0:
        bit_str += '0'

    groups = [bit_str[i:i+8] for i in range(0, len(bit_str), 8)]

    for group in groups:
        decoded_text += chr(int(group, 2))

    return decoded_text
