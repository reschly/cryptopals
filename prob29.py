#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 29
# Break a SHA-1 keyed MAC using length extension

# To implement the attack, first write the function that computes the MD
# padding of an arbitrary message and verify that you're generating the
# same padding that your SHA-1 implementation is using. This should take
# you 5-10 minutes.

# first, create a "nopad" sha by removing a couple line from the code from problem 28
# comments removed just to help me see the code on a single screen
# also allow user to set state variables

import struct
from prob28 import dumbHashAuth
from prob1 import hexToRaw, rawToHex

def _left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def nopaddingSHA(message, h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0):
    #### REMOVED ####
    # message += b'\x80'
    # message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    # message += struct.pack('>Q', original_bit_len)

    for i in range(0, len(message), 64):
        w = [0] * 80
        for j in range(16):
            w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]
        for j in range(16, 80):
            w[j] = _left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
    
        for i in range(80):
            if 0 <= i <= 19:
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
    
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
    
    # Produce the final hash value (big-endian):
    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)


# mostly a copy of a lines from the copied sha implementation on problem 28:
def generateSHAPadding(message_length_in_bytes):
    return b'\x80' + (b'\x00' * ((56 - (message_length_in_bytes + 1) % 64) % 64)) + struct.pack('>Q', message_length_in_bytes*8)


# Now, take the SHA-1 secret-prefix MAC of the message you want to forge
# --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1
# registers (SHA-1 calls them "a", "b", "c", &c).
# Modify your SHA-1 implementation so that callers can pass in new
# values for "a", "b", "c" &c (they normally start at magic
# numbers). With the registers "fixated", hash the additional data you
# want to forge.

# Using this attack, generate a secret-prefix MAC under a secret key
# (choose a random word from /usr/share/dict/words or something) of the
# string:

hash_secret = b'YELLOW SUBMARINE'

def checkDumbHashAuth(message, tag):
    return (dumbHashAuth(hash_secret, message) == tag)

def appendMessage(original, tag, extra):    
    #assume secret is between 0 and 64 bytes in length
    for i in range(65):
        oldpadding = generateSHAPadding(len(original)+i);
        newpadding= generateSHAPadding(len(original) + len(oldpadding) + len(extra) + i);
        newdata = extra + newpadding;
        a = int.from_bytes(tag[0:4], byteorder='big');
        b = int.from_bytes(tag[4:8], byteorder='big');
        c = int.from_bytes(tag[8:12], byteorder='big');
        d = int.from_bytes(tag[12:16], byteorder='big');
        e = int.from_bytes(tag[16:20], byteorder='big');        
        newtag = hexToRaw(nopaddingSHA(newdata, h0=a, h1=b, h2=c, h3=d, h4=e))
        if (checkDumbHashAuth(original + oldpadding + extra, newtag)):
            return newtag
    print("Failure");
    

def test29():
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    tag = dumbHashAuth(hash_secret, message)
    newtag = appendMessage(message, tag, b';admin=true');
    print("new tag = ", rawToHex(newtag))
    print("Problem 29 success")

if (__name__ == "__main__"):
    test29();