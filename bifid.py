from array import *
import sys

# Example key generation using bash:
#
# seq 0 255 | shuf | while read num; do
#   printf "$(printf '\\%03o' "$num")";
# done > bifid.key
def load_key(data):
    square = [ [ 0 for i in range(16) ] for j in range(16) ]

    for i in range(16):
        for j in range(16):
            square[i][j] = data[i*16+j]

    return square

def encrypt(plaintext, square):
    list1 = [];
    list2 = [];
    encrypted = bytearray()

    for k in range(len(plaintext)):
        byte = plaintext[k]

        # take each byte, get i,j values,
        # and add to list1,list2 respectively
        count = 0;
        for i in range(16):
            for j in range(16):
                if square[i][j] == byte:
                    list1.append(i)
                    list2.append(j)
                count += 1

    # pair values of list1+list2,
    # and output new byte values from square

    # handle even number of bytes
    # - pair list1
    # - pair list2)
    if len(list1) % 2 == 0:
        for i in range(0, len(list1) - 1, 2):
            encrypted.append(square[list1[i]][list1[i+1]])
        for i in range(0, len(list2) - 1, 2):
            encrypted.append(square[list2[i]][list2[i+1]])

    # handle odd number of bytes:
    # - pair list1 except last
    # - pair list1(last) and list2(first)
    # - pair list2 except first
    else:
        for i in range(0, len(list1) - 2, 2):
            encrypted.append(square[list1[i]][list1[i+1]])
        encrypted.append(square[list1[len(list1)-1]][list2[0]])
        for i in range(1, len(list2) - 1, 2):
            encrypted.append(square[list2[i]][list2[i+1]])

    return encrypted

def decrypt(ciphertext, square):
    list1 = [];
    list2 = [];
    decrypted = bytearray()

    for k in range(len(ciphertext)):
        # find i,j values from byte
        i = 0
        j = 0
        for i2 in range(16):
            for j2 in range(16):
                if square[i2][j2] == ciphertext[k]:
                    i = i2
                    j = j2
                    break;

        # handle even number of bytes case:
        # - first half of i,j values goes to list1
        # - second half of i,j values goes to list2
        if len(ciphertext) % 2 == 0:
            if k < len(ciphertext)/2:
                list1.append(i)
                list1.append(j)
            else:
                list2.append(i)
                list2.append(j)

        # handle odd number of bytes case
        # - i,j values before middle pair go to list1
        # - i from middle pair goes to list1
        # - j from muddle pair goes to list2
        # - i,j values after middle pair go to list2
        else:
            if k < (len(ciphertext) - 1)/2:
                list1.append(i)
                list1.append(j)
            elif k == (len(ciphertext) - 1)/2:
                list1.append(i)
                list2.append(j)
            else:
                list2.append(i)
                list2.append(j)

    # get byte value from i,j values stored in list1,list2 respectively
    for i in range(len(list1)):
        decrypted.append(square[list1[i]][list2[i]])

    return decrypted
