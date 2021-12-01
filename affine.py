import sys

# the modulus of one 8-bit byte
m = 256

# Note:
# E(x) = (ax+b) mod m
#      = ((ax mod m) + (b mod m)) mod m
#      = (((a mod m)(x mod m) mod m + (b mod m)) mod m
# therefore, a and b are in the domain of 0 to m (non-inclusive)
# therefore, a and b are each one byte
#
# For modulo arithmetic rules:
# See: https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/modular-addition-and-subtraction
# See: https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/modular-multiplication
#
# Note: a must be one of the following 128 values:
#
# 1 3 5 7 9 11 13 15 17 19 21 23 25 27 29 31 33 35 37 39 41 43 45 47 49
# 51 53 55 57 59 61 63 65 67 69 71 73 75 77 79 81 83 85 87 89 91 93 95
# 97 99 101 103 105 107 109 111 113 115 117 119 121 123 125 127 129 131
# 133 135 137 139 141 143 145 147 149 151 153 155 157 159 161 163 165
# 167 169 171 173 175 177 179 181 183 185 187 189 191 193 195 197 199
# 201 203 205 207 209 211 213 215 217 219 221 223 225 227 229 231 233
# 235 237 239 241 243 245 247 249 251 253 255
#
# The above acceptable values for a were generated with the following:
# for a in range(m):
#     for x in range(m):
#         if ((a%m) * (x%m)) % m == 1:
#             print(a)
#             break
#
# The following bash command can be used to generate a key with an
# acceptable a value:
#
# printf "$(printf '\\%03o\\%03o' "$(
#   for a in $(seq 0 256); do
#     for x in $(seq 0 256); do
#       if [ "$(( (a*x)%256 ))" -eq 1 ]; then
#         echo "$a"
#         break
#       fi
#     done
#   done | shuf | head -n1
# )" "$((RANDOM % 256))")" > affine.key
def load_key(data):
    key = {}

    key["a"] = data[0]
    key["b"] = data[1]

    return key

def encrypt(plaintext, key):
    a = key["a"]
    b = key["b"]

    encrypted = bytearray()

    for k in range(len(plaintext)):
        byte = plaintext[k]

        # E(x) = (ax+b) mod m
        encrypted.append((a*byte+b)%m)
    return encrypted

def decrypt (ciphertext, key):
    a = key["a"]
    b = key["b"]

    # naively solve for a_inv for congruence modulo
    # by finding x value that satisfies (a*x)%m=1
    #
    # Example:
    # a_inv = 21 for a=5, b=8, and m=26 (example from Wikipedia)
    #
    # Note: a_inv will default to 0 if a valid coprime value was not found
    a_inv = 0
    for x in range(m):
        if ((a%m) * (x%m)) % m == 1:
            a_inv = x
            break
    #print(a_inv)

    decrypted = bytearray()

    for k in range(len(ciphertext)):
        byte = ciphertext[k]

        # D(x) = a_inv*(x-b) mod m
        decrypted.append((a_inv*(byte-b))%m)
    return decrypted
