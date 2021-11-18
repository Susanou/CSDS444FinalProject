from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, size, ceil_div
from Crypto.PublicKey import RSA # ONLY USED TO READ a .pem key file not used for the actual algorithm
from Crypto.Hash import SHA1
from Crypto.Signature.pss import MGF1
from Crypto import Random
from Crypto.Util.py3compat import bord

from pwn import xor

def generate(bit_length=2048):
    key = RSA.generate(bit_length)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    
    public_key = key.publickey().export_key()
    with open("public.pem", "wb") as f:
        f.write(public_key)

def encrypt(m_file, k_file):
    with open(m_file, "rb") as f:
        plaintext = f.read()
    
    with open(k_file, "rb") as f:
        key = RSA.import_key(f.read())
    

    # RFC3447 to see the algorithm section 7.1.1
    mod_bits = size(key.n)
    k = ceil_div(mod_bits, 8) # from bits to bytes
    hash_len = SHA1.digest_size
    message_len = len(plaintext) 

    padding_len = k - message_len - 2*hash_len - 2
    if padding_len < 0:
        raise ValueError("Plaintext too long")

    l_hash = SHA1.new(b'').digest()
    ps = b'\x00' * padding_len
    db = l_hash + ps + b'\x01' + plaintext

    r_seed = Random.get_random_bytes(hash_len)

    db_mask = MGF1(r_seed, k-hash_len-1, SHA1)

    masked_db = xor(r_seed, db_mask)

    seed_mask = MGF1(masked_db, hash_len, SHA1)

    masked_seed = xor(r_seed, seed_mask)

    encrypted_message = b'\x00' + masked_seed + masked_db
    em_int = bytes_to_long(encrypted_message)
    m_int = pow(em_int, key.e, key.n)

    c = long_to_bytes(m_int, k)
    return c

def decrypt(m_file, k_file):
    with open(m_file, "rb") as f:
        ciphertext = f.read()
    
    with open(k_file, "rb") as f:
        key = RSA.import_key(f.read())
    
    # RFC3447 to see the algorithm section 7.1.2
    mod_bits = size(key.n)
    k = ceil_div(mod_bits, 8) # from bits to bytes
    hash_len = SHA1.digest_size

    if len(ciphertext) != k or k < hash_len+2:
        raise ValueError("Cipher text with incorrect length")
    
    ciphertext_int = bytes_to_long(ciphertext)

    message_int = pow(ciphertext_int, key.d, key.n)
    em = long_to_bytes(message_int, k)

    l_hash = SHA1.new(b'').digest()

    y = em[0]
    masked_seed = em[1:hash_len+1]
    masked_db = em[hash_len+1:]

    seed_mask = MGF1(masked_db, hash_len, SHA1)
    seed = xor(masked_seed, seed_mask)

    db_mask = MGF1(seed, k-hash_len-1, SHA1)
    db = xor(db_mask, masked_db)

    one_b_pos = hash_len + db[hash_len:].find(b'\x01')
    l_hash_1 = db[:hash_len]
    invalid = bord(y) | int(one_b_pos < hash_len)
    hash_comp = xor(l_hash_1, l_hash)

    for x in hash_comp:
        invalid |= bord(x)
    for x in db[hash_len:one_b_pos]:
        invalid |= bord(x)
    
    if invalid != 0:
        raise ValueError("Incorrect decryption")
    
    return db[one_b_pos+1:]
