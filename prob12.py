#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 12
# Byte-at-a-time ECB decryption, Full control version

from prob11 import generateAESKey
from prob9 import addPKCS7Padding
from prob10 import aes_ecb_enc
from prob1 import base64toRaw
from prob8 import chunks

# Copy your oracle function to a new function that encrypts buffers
# under ECB mode using a consistent but unknown key (for instance,
# assign a single random key, once, to a global variable).

global_aes_key = generateAESKey();
def constant_ecb_encrypt(rawInput):
    return aes_ecb_enc(addPKCS7Padding(rawInput, 16), global_aes_key);

# Now take that same function and have it append to the plaintext,
# BEFORE ENCRYPTING, the following string:

def append_and_encrypt(rawInput):
    unknownB64 = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' + \
    b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' + \
    b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' + \
    b'YnkK'
    unknownRaw = base64toRaw(unknownB64);
    return constant_ecb_encrypt(rawInput + unknownRaw);

# What you have now is a function that produces:
# AES-128-ECB(your-string || unknown-string, random-key)

# You can decrypt "unknown-string" with repeated calls to the oracle
# function!

# Here's roughly how:

# a. Feed identical bytes of your-string to the function 1 at a time ---
# start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the
# block size of the cipher. You know it, but do this step anyway.

def determineBlockSize():
    plaintext = b'';
    size1 = len(append_and_encrypt(plaintext));
    plaintext += b'A';
    size2 = len(append_and_encrypt(plaintext));
    while (size1 == size2): # continue until we expand to a new block
        plaintext += b'A';
        size2 = len(append_and_encrypt(plaintext));
    return (size2 - size1);

def determinePlaintextLength():
    plaintext = b'';
    emptyCipherLength = len(append_and_encrypt(plaintext));
    maxPlaintextLength = emptyCipherLength - 1; # cipher = plain + (at least) 1 byte PKCS7 padding
    while (True):
        plaintext += b'A';
        thisCipherLength = len(append_and_encrypt(plaintext));
        if (thisCipherLength == emptyCipherLength):
            maxPlaintextLength -= 1; 
        else:
            return maxPlaintextLength;
    
    
# b. Detect that the function is using ECB. You already know, but do
# this step anyways.

def detectMode():
    plaintext = b'A' * 48; 
    cipher = append_and_encrypt(plaintext);
    blocks = chunks(cipher, 16);
    if (blocks[1] == blocks[2]):
        return "ECB";
    else:
        return "NOT ECB";

# c. Knowing the block size, craft an input block that is exactly 1 byte
# short (for instance, if the block size is 8 bytes, make
# "AAAAAAA"). Think about what the oracle function is going to put in
# that last byte position.
# d. Make a dictionary of every possible last byte by feeding different
# strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB",
# "AAAAAAAC", remembering the first block of each invocation.
# e. Match the output of the one-byte-short input to one of the entries
# in your dictionary. You've now discovered the first byte of
# unknown-string.
padStr = b'A';
def determineNextByte(rawPrefix, observedCipher):
    ''' Given a prefix, generates 256 blocks of the form:
    AA..AA|prefix|?, and checks for a match against the observed cipher
    '''
    blockSize = determineBlockSize()
    plain = (padStr) * (blockSize - 1 - len(rawPrefix));
    plain += rawPrefix;
    for i in range(256):
        thisPlain = plain + bytes(chr(i), 'UTF-8');
        thisCipher = append_and_encrypt(thisPlain);
        if (chunks(thisCipher, blockSize)[0] == observedCipher):
            return bytes(chr(i), 'UTF-8');
    return b'***ERROR***';

def determinePlaintext():
    blockSize = determineBlockSize()    
    plaintextLength = determinePlaintextLength();
    knownPlaintext = b'';
    for i in range(plaintextLength):
        # Set first unknown byte to be last byte in block
        padLen = (blockSize - 1) - (len(knownPlaintext) % blockSize);
        pad = padStr * padLen;
        # Collect cipher, identify cipher blocks of interest
        cipherOutput = append_and_encrypt(pad);
        blockOfInterest = len(knownPlaintext) // 16;
        cipherChunks = chunks(cipherOutput, blockSize);
        cipherOfInterest = cipherChunks[blockOfInterest];
        ###knownPlainChunks.append(b'');
        # prefix is last 15 bytes of (pad|knownPlaintext)
        prefix = (pad + knownPlaintext)[-15:];
        knownPlaintext += determineNextByte(prefix, cipherOfInterest);
    return knownPlaintext;
        


if __name__ == "__main__":
    print("Block size: " + str(determineBlockSize()));
    print("Mode: " + detectMode());
    print("Plaintext: " + str(determinePlaintext()));