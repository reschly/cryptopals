#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 11
# Write an oracle function and use it to detect ECB.
# Now that you have ECB and CBC working:
# Write a function to generate a random AES key; that's just 16 random bytes.

# Write a function that encrypts data under an unknown key --- that is,
# a function that generates a random key and encrypts under it.
# The function should look like:
# encryption_oracle(your-input)
# => [MEANINGLESS JIBBER JABBER]
# Under the hood, have the function APPEND 5-10 bytes (count chosen
# randomly) BEFORE the plaintext and 5-10 bytes AFTER the plaintext.

# Now, have the function choose to encrypt under ECB 1/2 the time, and
# under CBC the other half (just use random IVs each time for CBC). Use
# rand(2) to decide which to use.

# Now detect the block cipher mode the function is using each time.

from ssl import RAND_bytes
from prob10 import aes_cbc_enc, aes_ecb_enc
from prob8 import chunks
from prob9 import addPKCS7Padding

def generateAESKey():
    return RAND_bytes(16);
    
def getOneRandomByte():
    byte = RAND_bytes(1);
    return byte[0];    
    
def encryption_oracle(rawInput):
    key = generateAESKey();
    iv = generateAESKey();
    prependAmount = 5 + (getOneRandomByte() % 6); #slight bias...
    appendAmount = 5 + (getOneRandomByte() % 6); #slight bias...
    plaintext = (b'x' * prependAmount) + rawInput + (b'y' * appendAmount);

    if ((getOneRandomByte() & 0x1)):
        return aes_ecb_enc(addPKCS7Padding(plaintext, 16), key);
    else:
        return aes_cbc_enc(addPKCS7Padding(plaintext, 16), key, iv);
    


def detectMode():
    plaintext = b'A' * 48; #ensure that 2nd, 3rd blocks of cipher have same plaintext
    cipher = encryption_oracle(plaintext);
    blocks = chunks(cipher, 16);
    if (blocks[1] == blocks[2]):
        print("ECB");
    else:
        print("CBC");



if __name__ == "__main__":
    for i in range(16):
        detectMode();
