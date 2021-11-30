from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime, size, ceil_div
from Crypto.PublicKey import RSA # ONLY USED TO READ a .pem key file not used for the actual algorithm
from Crypto.Hash import SHA1
from Crypto.Signature.pss import MGF1
from Crypto import Random
from Crypto.Util.py3compat import bord, _copy_bytes

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
        message = f.read()
    
    with open(k_file, "rb") as f:
        key = RSA.import_key(f.read())
    

    # RFC3447 to see the algorithm section 7.1.1
    modBits = size(key.n)
    k = ceil_div(modBits, 8) # Convert from bits to bytes
    hLen = SHA1.digest_size
    mLen = len(message)

    # Step 1b
    ps_len = k - mLen - 2 * hLen - 2
    if ps_len < 0:
        raise ValueError("Plaintext is too long.")
    # Step 2a
    lHash = SHA1.new(b'').digest()
    # Step 2b
    ps = b'\x00' * ps_len
    # Step 2c
    db = lHash + ps + b'\x01' + _copy_bytes(None, None, message)
    # Step 2d
    ros = Random.get_random_bytes(hLen)
    # Step 2e
    dbMask = MGF1(ros, k-hLen-1, SHA1)
    # Step 2f
    maskedDB = xor(db, dbMask)
    # Step 2g
    seedMask = MGF1(maskedDB, hLen, SHA1)
    # Step 2h
    maskedSeed = xor(ros, seedMask)
    # Step 2i
    em = b'\x00' + maskedSeed + maskedDB
    # Step 3a (OS2IP)
    em_int = bytes_to_long(em)
    # Step 3b (RSAEP)
    m_int = int(pow(em_int, key.e, key.n))
    # Step 3c (I2OSP)
    c = long_to_bytes(m_int, k)
    return c

def decrypt(m_file, k_file):
    with open(m_file, "rb") as f:
        ciphertext = f.read()
    
    with open(k_file, "rb") as f:
        key = RSA.import_key(f.read())
    
    if not key.has_private():
        raise TypeError("This is not a private key")

    # RFC3447 to see the algorithm section 7.1.2
    modBits = size(key.n)
    k = ceil_div(modBits,8) # Convert from bits to bytes
    hLen = SHA1.digest_size

    # Step 1b and 1c
    if len(ciphertext) != k or k<hLen+2:
        raise ValueError("Ciphertext with incorrect length.")
    # Step 2a (O2SIP)
    ct_int = bytes_to_long(ciphertext)
    # Step 2b (RSADP)
    m_int = int(pow(ct_int, key.d, key.n))
    # Complete step 2c (I2OSP)
    em = long_to_bytes(m_int, k)
    # Step 3a
    lHash = SHA1.new(b'').digest()
    # Step 3b
    y = em[0]
    # y must be 0, but we MUST NOT check it here in order not to
    # allow attacks like Manger's (http://dl.acm.org/citation.cfm?id=704143)
    maskedSeed = em[1:hLen+1]
    maskedDB = em[hLen+1:]
    # Step 3c
    seedMask = MGF1(maskedDB, hLen, SHA1)
    # Step 3d
    seed = xor(maskedSeed, seedMask)
    # Step 3e
    dbMask = MGF1(seed, k-hLen-1, SHA1)
    # Step 3f
    db = xor(maskedDB, dbMask)
    # Step 3g
    one_pos = hLen + db[hLen:].find(b'\x01')
    lHash1 = db[:hLen]
    invalid = bord(y) | int(one_pos < hLen)
    hash_compare = xor(lHash1, lHash)
    for x in hash_compare:
        invalid |= bord(x)
    for x in db[hLen:one_pos]:
        invalid |= bord(x)
    if invalid != 0:
        raise ValueError("Incorrect decryption.")
    # Step 4
    return db[one_pos + 1:]
