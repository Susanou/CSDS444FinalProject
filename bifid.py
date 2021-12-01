from array import *
import sys

# naive square generation (not shuffled, not secure)
"""
square = [ [ 0 for i in range(16) ] for j in range(16) ]
count = 0;
for i in range(16):
    for j in range(16):
        square[i][j] = count
        #print("square[%d][%d] = %d" % (i,j,count))
        count += 1
"""

# pre-shuffled square example
#
# Produced by the following bash commands:
# printf 'square=[\n';
# i=0;
# seq 0 255 | while read num; do
#   printf '0x%02x\n' "$num";
# done | shuf | while read num; do
#   if [ "$i" -eq 0 ]; then
#     printf '    [ ';
#   fi;
# 
#   if [ "$i" -lt 15 ]; then
#     printf '%s, ' "$num";
#     i="$(($i+1))";
#   else
#     printf '%s ],\n' "$num"; i="0";
#   fi;
# done;
# printf ']\n'
square=[
    [ 0xa7, 0xc3, 0xee, 0xcb, 0xc5, 0xbe, 0xa2, 0x90, 0x80, 0xe5, 0x93, 0xe6, 0xa4, 0x82, 0xe7, 0x8e ],
    [ 0x3e, 0x4a, 0xb1, 0x1a, 0xbc, 0x8d, 0xff, 0x03, 0xce, 0xbf, 0x19, 0x09, 0xf4, 0xa9, 0xe8, 0xc4 ],
    [ 0x13, 0x65, 0xe0, 0x18, 0x94, 0xbb, 0x59, 0x31, 0xfc, 0x47, 0xd5, 0x7a, 0xda, 0x76, 0x79, 0xe9 ],
    [ 0x7b, 0xb5, 0x48, 0x58, 0xc7, 0xbd, 0xed, 0xb3, 0x7f, 0x35, 0x57, 0x07, 0xef, 0x68, 0x56, 0x95 ],
    [ 0xfb, 0x15, 0xaf, 0x36, 0x6c, 0x71, 0x45, 0x30, 0x21, 0xf3, 0x1f, 0xd6, 0xa3, 0x84, 0x00, 0x64 ],
    [ 0x77, 0x5e, 0x67, 0x05, 0x6b, 0x6f, 0xf9, 0x7d, 0xb2, 0x9b, 0x96, 0xaa, 0x50, 0x06, 0x6d, 0x46 ],
    [ 0x4b, 0xad, 0x0a, 0xea, 0x10, 0x39, 0x70, 0x4c, 0xc2, 0x7e, 0xf6, 0x40, 0xcf, 0xdb, 0x92, 0x89 ],
    [ 0x42, 0xfe, 0x37, 0x8c, 0x2e, 0x8f, 0xd0, 0xca, 0x11, 0x6a, 0x29, 0xb4, 0x33, 0x41, 0x0c, 0x0d ],
    [ 0xa5, 0xfa, 0x32, 0x38, 0x54, 0xb0, 0xfd, 0xc9, 0x85, 0xdc, 0xb6, 0x43, 0xd1, 0x99, 0xdf, 0xe1 ],
    [ 0xec, 0xdd, 0xe2, 0xa0, 0x2d, 0x26, 0xcd, 0xc0, 0xf7, 0x2b, 0x62, 0x7c, 0x61, 0xf2, 0x9d, 0x63 ],
    [ 0xd8, 0x53, 0x08, 0xb9, 0x0b, 0xf0, 0x9c, 0x0f, 0x9e, 0x01, 0xb8, 0xd3, 0xac, 0x5f, 0xa1, 0x23 ],
    [ 0x98, 0x86, 0x16, 0xa6, 0xc1, 0xba, 0x52, 0x4e, 0xf5, 0x17, 0xe4, 0x27, 0xab, 0x73, 0x3f, 0xae ],
    [ 0xe3, 0x1c, 0x4d, 0x66, 0x3b, 0x4f, 0x3c, 0xc8, 0x25, 0xd4, 0x83, 0x5b, 0x02, 0x2c, 0x97, 0x6e ],
    [ 0x44, 0x2a, 0xc6, 0xf8, 0x78, 0x81, 0x74, 0xd2, 0x51, 0x34, 0xde, 0xf1, 0x22, 0x14, 0x24, 0x1e ],
    [ 0xeb, 0xcc, 0x72, 0xa8, 0x87, 0x5c, 0xb7, 0x8a, 0x1b, 0x75, 0x12, 0x0e, 0x28, 0xd7, 0x3d, 0x55 ],
    [ 0x9a, 0x5d, 0x1d, 0x91, 0x49, 0x8b, 0x9f, 0x20, 0x3a, 0x2f, 0x04, 0xd9, 0x60, 0x69, 0x88, 0x5a ],
]

def encrypt(plaintext):
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

def decrypt(ciphertext):
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
