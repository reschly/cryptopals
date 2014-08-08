#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 27
# CBC bit flipping
from prob11 import generateAESKey
from prob10 import aes_cbc_dec, aes_cbc_enc
from prob18 import raw_xor
from symbol import except_clause

# Recover the key from CBC with IV=Key

# Take your code from the CBC exercise (16) and modify it so that it
# repurposes the key for CBC encryption as the IV. Applications
# sometimes use the key as an IV on the auspices that both the sender
# and the receiver have to know the key already, and can save some space
# by using it as both a key and an IV.

global_aes_key = generateAESKey();
global_iv = global_aes_key;

# Using the key as an IV is insecure; an attacker that can modify
# ciphertext in flight can get the receiver to decrypt a value that will
# reveal the key.

# The  CBC code from exercise 16 encrypts a URL string. Verify each byte
# of the plaintext for ASCII compliance (ie, look for high-ASCII
# values). Noncompliant messages should raise an exception or return an
# error that includes the decrypted plaintext (this happens all the time
# in real systems, for what it's worth).

def checkAscii(s):
    for b in s:
        if b >= 128:
            return False;
    return True;

def decryptAndCheckAscii(cip):
    rawPlain = aes_cbc_dec(cip, global_aes_key, global_iv);
    if (checkAscii(rawPlain)):
        return (True, b'');
    else:
        return (False, rawPlain);


def recoverKey():
    # Use your code to encrypt a message that is at least 3 blocks long:
    #  AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
    plaintext = (b'A' * 48);
    cipher = aes_cbc_enc(plaintext, global_aes_key, global_iv);

    #Modify the message (you are now the attacker):
    #   C_1, C_2, C_3 -> C_1, 0, C_1
    modifiedCipher = cipher[0:16] + (b'\x00' * 16) + cipher[0:16];

    # Decrypt the message (you are now the receiver) and raise the
    # appropriate error if high-ASCII is found.
    (checkAsciiResult, errorString) = decryptAndCheckAscii(modifiedCipher);

    # As the attacker, recovering the plaintext from the error, extract the key:
    #  P'_1 XOR P'_3
    if (checkAsciiResult):
        raise Exception("Unlucky");
    key = raw_xor(errorString[0:16], errorString[32:48]);
    return key;

if __name__ == "__main__":
    try:
        recoveredKey = recoverKey();
        if (recoveredKey == global_aes_key):
            print("Problem 27 success");
        else:
            print("Problem 27 failure");
    except Exception:
        print("Unlucky failure.  Try again");