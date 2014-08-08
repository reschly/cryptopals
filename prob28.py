#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 28
# Implement a SHA-1 keyed MAC

# Find a SHA-1 implementation in the language you code in. Do not use
# the SHA-1 implementation your language already provides (for instance,
# don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby,
# you'd want a pure-Ruby SHA-1).

# the below is a copy/paste from https://github.com/ajalt/python-sha1/blob/master/sha1.py
# edited to be python3 friendly
import struct
from prob1 import hexToRaw
import hashlib # just to verify

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff
    
def sha1_from_github(message):
    """SHA-1 Hashing Function

    A custom SHA-1 hashing function implemented entirely in Python.

    Arguments:
        message: The input message string to hash.

    Returns:
        A hex SHA-1 digest of the input message.
    """
    # Initialize variables:
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    
    # Pre-processing:
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    # append the bit '1' to the message
    message += b'\x80'
    
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message += struct.pack('>Q', original_bit_len)
    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for i in range(0, len(message), 64):
        w = [0] * 80
        # break chunk into sixteen 32-bit big-endian words w[i]
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
        # Extend the sixteen 32-bit words into eighty 32-bit words:
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
    
        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid ~
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
    
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
    
        # sAdd this chunk's hash to result so far:
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

# the above is a copy/paste from https://github.com/ajalt/python-sha1_from_github/blob/master/sha1_from_github.py

# Write a function to authenticate a message under a secret key by using
# a secret-prefix MAC, which is simply:
#  SHA1(key || message)

def dumbHashAuth(key, message):
    return hexToRaw(sha1_from_github(key + message));
    

# Verify that you cannot tamper with the message without breaking the
# MAC you've produced, and that you can't produce a new MAC without
# knowing the secret key.

def testDumHashAuth():
    key = b'YELLOW SUBMARINE'
    message1 = b'Four Score And Seven Years Ago';
    message2 = b'Four Score and Eight Years Ago';
    # tamper check
    tag1 = dumbHashAuth(key, message1);
    tag2 = dumbHashAuth(key, message2);
    if (tag1 == tag2):
        print("Problem 28 failure");
        return False;
    # produce new mack check
    forgedTag = dumbHashAuth(b'', message1);
    if (tag1 == forgedTag):
        print("Problem 28 failure");
        return False;
    print("Problem 28 success");
    return True;

if __name__ == "__main__":
    # verify code from github against hashlib
    if (hashlib.sha1(b'YELLOW SUBMARINE').hexdigest() != sha1_from_github(b'YELLOW SUBMARINE')):
        print("sha1 failure");
    testDumHashAuth();