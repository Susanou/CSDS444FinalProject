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



# two random values for our "key" a and b
# TODO: ensure that a and m are coprime
a = 71
b = 23



# Open plaintext file
file = open("smile1.png", "rb")

# Read all bytes from plaintext file
data = []
while True:
    byte = file.read(1)
    if not byte:
        break
    data.append(byte)

# encrypt plaintext data into ciphertext data
var = encrypt(data, a, b)

# write all bytes to ciphertext file
f = open("smile1-affine.png.enc", "wb")
for i in range(len(var)):
    f.write(var[i])
f.close()

# open ciphertext file
file = open("smile1-affine.png.enc", "rb")



# Read all bytes from ciphertext file
data = []
while True:
    byte = file.read(1)
    if not byte:
        break
    data.append(byte)

# decrypt ciphertext data back to plaintext data
var = decrypt(data, a, b)

# write all bytes to decrypted plaintext file
f = open("smile1-affine-decrypted.png", "wb")
for i in range(len(var)):
    f.write(var[i])
f.close()
