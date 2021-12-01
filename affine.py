import sys

# the modulus of one 8-bit byte
m = 256

def encrypt(plaintext, a, b):
    encrypted = [];

    for k in range(len(plaintext)):
        byte = plaintext[k]
        byte_as_int = int.from_bytes(byte, byteorder=sys.byteorder)

        # E(x) = (ax+b) mod m
        encrypted.append(((a*byte_as_int+b)%m).to_bytes(1, byteorder=sys.byteorder))
    return encrypted

def decrypt (ciphertext, a, b):
    # naively solve for a_inv for congruence modulo
    # by finding x value that satisfies (a*x)%m=1
    #
    # Example:
    # a_inv = 21 for a=5, b=8, and m=26 (example from Wikipedia)
    a_inv = 0
    for x in range(m):
        if ((a%m) * (x%m)) % m == 1:
            a_inv = x
            break
    #print(a_inv)

    decrypted = [];

    for k in range(len(ciphertext)):
        byte = ciphertext[k]
        byte_as_int = int.from_bytes(byte, byteorder=sys.byteorder)

        # D(x) = a_inv*(x-b) mod m
        decrypted.append(((a_inv*(byte_as_int-b))%m).to_bytes(1, byteorder=sys.byteorder))
    return decrypted
