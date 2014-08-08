#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 25
# Break "random access read/write AES CTR
from prob7 import doProb7
from prob11 import generateAESKey
from prob18 import aes_ctr, raw_xor


# Back to CTR. Encrypt the recovered plaintext from
#     https://gist.github.com/3132853
# (the ECB exercise) 
# under CTR with a random key (for this exercise the
# key should be unknown to you, but hold on to it).
plaintext = doProb7();
key = generateAESKey();
iv = b'\x00' * 16;
cipher = aes_ctr(plaintext, key, iv);

# Now, write the code that allows you to "seek" into the ciphertext,
# decrypt, and re-encrypt with different plaintext. Expose this as a
# function, like, "edit(ciphertext, key, offet, newtext)".
def editCipher(cipher, key, offset, new):
    oldPlain = aes_ctr(cipher, key, iv);
    newPlain = oldPlain[0:offset] + new + oldPlain[offset+len(new):];
    newCipher = aes_ctr(newPlain, key, iv);
    return newCipher;


# Imagine the "edit" function was exposed to attackers by means of an
# API call that didn't reveal the key or the original plaintext; the
# attacker has the ciphertext and controls the offset and "new text".
# Recover the original plaintext.

# create the API function
def editAPI(cipher, offset, new):
    return editCipher(cipher, key, offset, new);

def recoverPlaintext():
    # start with the cipher
    originalCipher = cipher;
    # edit the plaintext to be all 0, recovering the raw keystream
    newPlain = b'\x00' * len(originalCipher);
    keystream = editAPI(originalCipher, 0, newPlain);
    # xor out the keystream from the original plaintext
    originalPlain = raw_xor(originalCipher, keystream);
    return originalPlain;

def testProb25():
    if (plaintext == recoverPlaintext()):
        print("Problem 25 success");
    else:
        print("Problem 25 failure");
        
if __name__ == "__main__":
    testProb25();
