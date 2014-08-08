#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 14
# Byte-at-a-time ECB decryption, Partial control version

from prob11 import getOneRandomByte
from prob1 import base64toRaw
from prob12 import constant_ecb_encrypt, padStr
from prob8 import chunks
from ssl import RAND_bytes

# Take your oracle function from #12. 
# Now generate a random count of random bytes and 
# prepend this string to every plaintext. You are now doing:
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

prefixValue = RAND_bytes(getOneRandomByte());# += bytes(chr(getOneRandomByte()), 'UTF-8');
def prob14Encrypt(rawInput):
    unknownB64 = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' + \
    b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' + \
    b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' + \
    b'YnkK'
    unknownRaw = base64toRaw(unknownB64);
    return constant_ecb_encrypt(prefixValue + rawInput + unknownRaw);

# Same goal: decrypt the target-bytes.
def recoverBytes():
    # first, determine number of bytes needed to push prefix up to a block boundry
    # and where the first block fully controlled by my input lies (effectively, determine prefix length)
    numBytesForPrefix, firstControlledBlock = determinePrefixLength();
    # deterine target plaintext length
    targetPlaintextLength = prob14DeterminePlaintextLength() + (numBytesForPrefix) - (firstControlledBlock * 16);
    # do the problem 12 process
    knownPlaintext = b'';  
    blockSize = 16; 
    for i in range(targetPlaintextLength):
        # Set first unknown byte to be last byte in block
        padLen = numBytesForPrefix + (blockSize - 1) - (len(knownPlaintext) % blockSize);
        pad = padStr * padLen;
        # Collect cipher, identify cipher blocks of interest
        cipherOutput = prob14Encrypt(pad);
        blockOfInterest = firstControlledBlock + (len(knownPlaintext) // 16);
        cipherChunks = chunks(cipherOutput, blockSize);
        cipherOfInterest = cipherChunks[blockOfInterest];
        ###knownPlainChunks.append(b'');
        # prefix is last 15 bytes of (pad|knownPlaintext)
        prefix = (pad + knownPlaintext)[-15:];
        knownPlaintext += prob14DetermineNextByte(prefix, cipherOfInterest, numBytesForPrefix, firstControlledBlock);
    return knownPlaintext;

def prob14DeterminePlaintextLength():
    plaintext = b'';
    emptyCipherLength = len(prob14Encrypt(plaintext));
    maxPlaintextLength = emptyCipherLength - 1; # cipher = plain + (at least) 1 byte PKCS7 padding
    while (True):
        plaintext += b'A';
        thisCipherLength = len(prob14Encrypt(plaintext));
        if (thisCipherLength == emptyCipherLength):
            maxPlaintextLength -= 1; 
        else:
            return maxPlaintextLength;
    

def prob14DetermineNextByte(rawPrefix, observedCipher, numBytesForPrefix, firstControlledBlock):
    blockSize = 16;
    plain = (padStr) * (numBytesForPrefix + blockSize - 1 - len(rawPrefix));
    plain += rawPrefix;
    for i in range(256):
        thisPlain = plain + bytes(chr(i), 'UTF-8');
        thisCipher = prob14Encrypt(thisPlain);
        if (chunks(thisCipher, blockSize)[firstControlledBlock] == observedCipher):
            return bytes(chr(i), 'UTF-8');
    return b'***ERROR***';

def determinePrefixLength():
    plainLength = 32;
    while (True):
        plain = b'A' * plainLength;
        cipher = prob14Encrypt(plain);
        cipherBlocks = chunks(cipher, 16);
        for i in range(len(cipherBlocks)-1):
            if (cipherBlocks[i] == cipherBlocks[i+1]):
                return (len(plain)%16), i;
        plainLength += 1;
    


'''What's harder about doing this?

How would you overcome that obstacle? The hint is: you're using
all the tools you already have; no crazy math is required.

Think about the words "STIMULUS" and "RESPONSE".'''
        
if __name__ == "__main__":
    print(recoverBytes());