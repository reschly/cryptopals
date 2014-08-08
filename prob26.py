#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 26
# CTR bit flipping
from prob11 import generateAESKey
from prob18 import aes_ctr, raw_xor

# There are people in the world that believe that CTR resists
# bit flipping attacks of the kind to which CBC mode is susceptible.

# Re-implement the CBC bitflipping exercise (16) from earlier to use CTR mode
# instead of CBC mode. Inject an "admin=true" token.

# Generate a random AES key.
global_aes_key = generateAESKey();
global_iv = b'\x00' * 16;

prefix = b'comment1=cooking%20MCs;userdata='
suffix = b';comment2=%20like%20a%20pound%20of%20bacon'
def encryptString(s):
    s = s.replace(b';', b'\';\'').replace(b'=', b'\'=\'');
    rawInput = prefix + s + suffix;
    rawOutput = aes_ctr(rawInput, global_aes_key, global_iv);
    return rawOutput;

# The second function should decrypt the string and look for the
# characters ";admin=true;" (or, equivalently, decrypt, split the string
# on ;, convert each resulting string into 2-tuples, and look for the
# "admin" tuple. Return true or false based on whether the string exists.
def decryptAndCheckAdmin(cip):
    rawPlain = aes_ctr(cip, global_aes_key, global_iv);
    strPlain = str(rawPlain).rstrip("b'");
    if ";admin=true;" in strPlain:
        return True;
    return False;

# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
def generateEncryptedAdminProfile():
    desiredComment = b';admin=true;';
    firstComment = b'\x00' * len(desiredComment);
    # encrypt my harmless plaintext
    firstEncProfile = encryptString(firstComment);
    # locate the encrypted version of my comment, extract encrypted form of comment
    offset = len(prefix);
    firstCipher = firstEncProfile[offset:offset+len(firstComment)];
    # make new profile
    newEncProfile = firstEncProfile[0:len(prefix)] + raw_xor(firstCipher, desiredComment) + firstEncProfile[len(prefix)+len(desiredComment):];
    return newEncProfile;
 
if __name__ == "__main__":
    # test =,; are removed properly
    if (decryptAndCheckAdmin(encryptString(b';admin=true;'))):
        raise Exception("padding quote failure");
    cip = generateEncryptedAdminProfile();
    if (decryptAndCheckAdmin(cip)):
        print("Problem 26 success");
    else:
        raise Exception("Generate admin faulre");
    