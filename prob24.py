#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 24
# Create the MT19937 Stream Cipher And Break It
from prob11 import getOneRandomByte
from prob21 import MT19937
from random import choice
from time import time
from prob1 import rawToBase64, base64toRaw

# You can create a trivial stream cipher out of any PRNG; use it to
# generate a sequence of 8 bit outputs and call those outputs a
# keystream. XOR each byte of plaintext with each successive byte of
# keystream.

# Write the function that does this for MT19937 using a 16-bit
# seed. Verify that you can encrypt and decrypt properly. This code
# should look similar to your CTR code.
def MTStreamCipher(seed, rawInput):
    mt = MT19937(seed);
    rawOutput = b'';
    mtOut = 0;
    for i in range(len(rawInput)):
        if (i % 4 == 0):
            mtOut = mt.extract_number();
        thisKey = (mtOut >> (8*(3-(i%4))))&0xff;
        rawOutput += (rawInput[i] ^ thisKey).to_bytes(1, byteorder='big');
    return rawOutput;


def MTStreamCipherTest():
    plain = b'ABCDEFGHIJKLMNOP';
    seed = 31415;
    if (MTStreamCipher(seed, MTStreamCipher(seed, plain)) != plain):
        raise Exception("MTStreamCipherTest fail");
    print("MTStreamCipherTest success");
    return;


# Use your function to encrypt a known plaintext (say, 14 consecutive
# 'A' characters) prefixed by a random number of random characters.
def doMTEncrypt():
    prefixLen = getOneRandomByte();
    seed = getOneRandomByte() * 256 + getOneRandomByte();
    prefix = b'';
    letters = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    for i in range(prefixLen):
        prefix += choice(letters).to_bytes(1, byteorder='big');
    rawInput = prefix + b'AAAAAAAAAAAAAA';
    return MTStreamCipher(seed, rawInput)

# From the ciphertext, recover the "key" (the 16 bit seed).
def breakMTEncrypt(rawCipher):
    for i in range(65536):
        plain = MTStreamCipher(i, rawCipher);
        if (plain[-14:] == b'AAAAAAAAAAAAAA'):
            return i;
    raise Exception("Unable to find seed");

# Use the same idea to generate a random "password reset token" using
# MT19937 seeded from the current time.
def generatePasswordToken():
    mt = MT19937(int(time()));
    rawOutput = b'';
    for i in range(6):
        rawOutput += mt.extract_number().to_bytes(4, byteorder='big');
    b64Output = rawToBase64(rawOutput);
    return b64Output;
        
# Write a function to check if any given password token is actually
# the product of an MT19937 PRNG seeded with the current time.'''
def checkPasswordToken(b64Token):
    rawToken = base64toRaw(b64Token);
    now = int(time());
    for i in range(-3600, 3600): # +/- one hour
        mt = MT19937(now + i);
        mtOutput = b'';
        for i in range(6):
            mtOutput += mt.extract_number().to_bytes(4, byteorder='big');
        if (rawToken == mtOutput):
            print("MT seed time = ", (now+i));
            return (now-i);
    print("Not an MT seed time");
    return (-1);


def testCheckPasswordToken():
    if (checkPasswordToken(generatePasswordToken()) < 0):
        raise Exception("Failed to recover password token seed time");
    if (checkPasswordToken(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA') > 0):
        raise Exception("Incorrectly recovered password token seed time");
    print("Check Password Token success");

if __name__ == "__main__":
    MTStreamCipherTest();
    cipher = doMTEncrypt();
    print("MT Encryption seed: ", breakMTEncrypt(cipher));
    testCheckPasswordToken();
    
    
    