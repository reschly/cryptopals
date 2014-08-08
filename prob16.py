#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 16
# 16. CBC bit flipping

from prob11 import generateAESKey
from prob10 import aes_cbc_enc, aes_cbc_dec
from prob9 import addPKCS7Padding
from prob15 import checkAndRemovePKCS7Padding
from prob8 import chunks
from prob2 import hex_xor
from prob1 import rawToHex, hexToRaw

# Generate a random AES key.
global_aes_key = generateAESKey();
global_iv = b'\x00' * 16;

# Combine your padding code and CBC code to write two functions.
# The first function should take an arbitrary input string, prepend the
# string:
#        "comment1=cooking%20MCs;userdata="
# and append the string:
#    ";comment2=%20like%20a%20pound%20of%20bacon"
# The function should quote out the ";" and "=" characters.
# The function should then pad out the input to the 16-byte AES block
# length and encrypt it under the random AES key.
prefix = "comment1=cooking%20MCs;userdata="
suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
def padAndEncryptString(s):
    s = s.replace(";", "';'").replace("=", "'='");
    strInput = prefix + s + suffix;
    rawInput = bytes(strInput, 'UTF-8');
    rawOutput = aes_cbc_enc(addPKCS7Padding(rawInput, 16), global_aes_key, global_iv);
    return rawOutput;


# The second function should decrypt the string and look for the
# characters ";admin=true;" (or, equivalently, decrypt, split the string
# on ;, convert each resulting string into 2-tuples, and look for the
# "admin" tuple. Return true or false based on whether the string exists.

def decryptAndCheckAdmin(cip):
    rawPlain = checkAndRemovePKCS7Padding(aes_cbc_dec(cip, global_aes_key, global_iv));
    strPlain = str(rawPlain).rstrip("b'");
    if ";admin=true;" in strPlain:
        return True;
    return False;

# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
def generateEncryptedAdminProfile():
    # get to a fresh block
    s = 'A' * (16 - (len(prefix) % 16));
    #locate the IV for my block
    myIVBlock = ((len(prefix) + len(s)) // 16) - 1;
    # add a known block value
    s += 'X' * 16;
    # encrypt
    cip = padAndEncryptString(s);
    # extract IV for block of interest
    allBlocks = chunks(cip, 16);
    myIV = allBlocks[myIVBlock];
    # xor in IV with desired value
    hexIV = rawToHex(myIV);
    hexKnown = rawToHex('X'*16);
    hexDesired = rawToHex(";admin=true;XXXX")
    newHexIV = hex_xor(hexIV, hex_xor(hexKnown, hexDesired));
    newIV = hexToRaw(newHexIV);
    # insert "error"
    allBlocks[myIVBlock] = newIV;
    myCipher = b'';
    for b in allBlocks:
        myCipher += b;
    return myCipher;

# Before you implement this attack, answer this question: why does CBC
# mode have this property?
'''Because the IV (previous cipher block) is xor'd against the ECB-decryption of
the current block to produce plaintext. 

original_plaintext = ECB_decrypt ^ IV, thus, if the IV has an error (IV ^ error):
new_plaintext = ECB_decrypt ^ (IV & error) = (ECB_decrypt ^ IV)^ error = original_plaintext ^ error

The wikipedia pictures makes this clear: http://en.wikipedia.org/wiki/File:Cbc_decryption.png '''

if __name__ == "__main__":
    # test =,; are removed properly
    if (decryptAndCheckAdmin(padAndEncryptString(";admin=true;"))):
        raise Exception("padding quote failure");
    cip = generateEncryptedAdminProfile();
    if (decryptAndCheckAdmin(cip)):
        print("Problem 16 success");
    else:
        raise Exception("Generate admin faulre");
    