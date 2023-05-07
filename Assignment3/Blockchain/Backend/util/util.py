import hashlib
from Crypto.Hash import RIPEMD160
from math import log
from hashlib import sha256
from Blockchain.Backend.core.EllepticCurve.EllepticCurve import BASE58_ALPHABET

#Two rounds of SHA256
def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def hash160(s):
    return RIPEMD160.new(sha256(s).digest()).digest()

#Take an integer and return the little-endian sequence of length
def int_to_little_endian(n, length):
    return n.to_bytes(length, 'little')

def bytes_needed(n):
    if n == 0:
        return 1
    return int(log(n, 256)) + 1

def endcode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def decode_base58(s):
    num = 0

    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)

    combined = num.to_bytes(25, byteorder= 'big')
    checksum = combined[-4:]

    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(f"Bad Address {checksum} {hash256(combined[:-4][:4])}")
    return combined[1:-4]

#Takes a byte sequence and returns an integer
def little_endian_to_int(b):
    return int.from_bytes(b, 'little')

#Encodes an integer as a variant
def encode_variant(i):
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else: 
        raise ValueError('Integer is too large: {}'.format(i))
    
#Take a list of binary hashes and retun a list that is half the length
def merkle_parent_level(hashes):
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = hash256(hashes[i] + hashes[i + 1])
        parent_level.append(parent)
    return parent_level

#Take a list of binary hashes and return merkle root
def merkle_root(hashes):
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]

#Read a variable integer from a stream
def read_variant(s):
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i

#Turn an integer into bits
def target_to_bits(target):
    raw_bytes = target.to_bytes(32, 'big')
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        exponent = len(raw_bytes) + 1
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::1] + bytes([exponent])
    return new_bits

def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256**(exponent - 3)