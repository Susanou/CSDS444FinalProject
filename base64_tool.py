def encrypt(message):

    # get unicode values for characters
    output = ''.join(bin(ord(char)) for char in message)
    # remove b's. There's probably a better way to do this...
    output = output.replace("b", "")
    #print('Binary Unicode of Output:', output)

    # make length multiple of 6
    if len(output) < 6:
        output = output + ('0'*(6-len(output)))
    else:
        output = output + ('0'*(len(output) % 6))
    #print('Binary Unicode of Output with extra 0s:', output)

    lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    cipher = ''
    # Get values for cipher from lookup table
    for x in range(1, int(len(output)/6 + 1)):
        cipher = cipher + lookup[int(output[(x - 1) * 6:x * 6], 2)]
    # append '=' at end of cipher to make multiple of 4
    if len(cipher) < 4:
        cipher = cipher + ('='*(4-len(cipher)))
    else:
        cipher = cipher + ('='*(len(cipher) % 4))
    #print("Cipher Text:", cipher)
    return cipher


def decrypt(encodedMessage):

    encodedMessage = encodedMessage.replace('=', '')
    encodedMessage = encodedMessage.replace(' ', '')

    lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    #print('Encoded Message:', encodedMessage)

    decoded_bin = ''
    # get binary values for table lookups of characters
    for char in encodedMessage:
        #num = lookup.find(char)
        messageBin = (bin(lookup.find(char))).replace('b', '')

        if len(messageBin) == 7:
            messageBin = messageBin[1:]
        elif len(messageBin) < 6:  # if length is less than 6, add 0s to the beginning
            messageBin = '0'*(6-len(messageBin)) + messageBin
        decoded_bin += messageBin
    # make multiple of 8 for unicode printing
    while len(decoded_bin) % 8 != 0:
        decoded_bin += '0'
    #print(decoded_bin)
    decoded_message = ''
    # create decoded message
    for x in range(1, int(len(decoded_bin) / 8 + 1)):
        decoded_message = decoded_message + chr(int(decoded_bin[(x - 1) * 8:x * 8], 2))

    return decoded_message

print(encrypt('MessageToBeEncoded'))
print(decrypt('TWVzc2FnZVRvQmVFbmNvZGVk'))
