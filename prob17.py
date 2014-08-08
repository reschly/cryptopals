#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 17
# 17. The CBC padding oracle

from prob1 import base64toRaw
from prob11 import generateAESKey, getOneRandomByte
from prob10 import aes_cbc_enc, aes_cbc_dec
from prob9 import addPKCS7Padding
from prob15 import checkAndRemovePKCS7Padding
from prob8 import chunks
from prob13 import removePKCS7Padding

# Combine your padding code and your CBC code to write two functions.
# The first function should select at random one of the following 10 strings:

b64Strings = [ b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 
              b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', 
              b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 
              b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 
              b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 
              b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 
              b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 
              b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 
              b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 
              b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93' ];
rawStrings = [base64toRaw(s) for s in b64Strings];

# generate a random AES key (which it should save for all future
# encryptions), 
aeskey = generateAESKey();

# pad the string out to the 16-byte AES block size and
# CBC-encrypt it under that key, providing the caller the ciphertext and
# IV.
def encryptString():
    myString = rawStrings[getOneRandomByte() % len(rawStrings)];
    iv = generateAESKey(); # it's a 16-byte value...
    myOut = aes_cbc_enc(addPKCS7Padding(myString, 16), aeskey, iv);
    return myOut, iv;

# The second function should consume the ciphertext produced by the
# first function, decrypt it, check its padding, and return true or
# false depending on whether the padding is valid.
def checkPadding(rawCipher, rawIV):
    rawOutput = aes_cbc_dec(rawCipher, aeskey, rawIV);
    try:
        checkAndRemovePKCS7Padding(rawOutput);
        return True;
    except:
        return False;

def setByte(array, offset, value):
    array = array[0:offset] + value.to_bytes(1, byteorder='big') + array[offset+1:len(array)];
    return array

# rawIV = initial IV
# revIndex = we are guessing revIndexth byte, counting backwards (0 = last byte, 1 = next-to-last, etc)
# x = guess for the revIndexth byte
# knownPlaintext = fill for bytes after revIndex.  Must be of length (revIndex)
def setIV(rawIV, revIndex, x, knownPlaintext):
    # convert (x,knownPlaintext) into 0000...00|x|knownPlaintext
    extendedPlaintext = b'\x00' * (len(rawIV) - len(knownPlaintext) - 1) + x.to_bytes(1, byteorder='big')  + knownPlaintext;
    # xor in the plaintext
    temp = b'';
    for i in range(len(rawIV)):
        temp += (rawIV[i] ^ extendedPlaintext[i]).to_bytes(1, byteorder='big');
    # now xor in the PKCS7 pad
    # side comment: I'm used to the TLS CBC padding scheme.
    # forgetting that this is different from PKCS7 cost me a night of debugging...
    pad = b'\x00' * (len(rawIV) - revIndex - 1) + ((revIndex+1).to_bytes(1, byteorder='big') * (revIndex+i));
    output = b'';
    for i in range(len(temp)):
        output += (temp[i] ^ pad[i]).to_bytes(1, byteorder='big');
    return output;
    


def recoverBlock(rawBlock, rawIV):
    recoveredPlaintext = b'';
    # for each byte in the block
    for i in range(len(rawBlock)):
        # guess that byte
        for x in range(256):
            # Set the IV for that guess
            thisIV = setIV(rawIV, i, x, recoveredPlaintext);
            # see if padding correct
            if (checkPadding(rawBlock, thisIV)):
                # found a good byte, likely the one we're looking for.
                # edge case: for the first recovery, there is a chance
                # the plaintext ends with \x0202 (or \x030303)
                # test by mucking with the next-to-last byte of the IV and trying again
                if (i == 0):
                    thisIV = setByte(thisIV, len(thisIV)-2, thisIV[len(thisIV)-2] ^ 0xff);
                    if (checkPadding(rawBlock, thisIV) == False):
                        # hit that unlikely edge case. Continue...
                        continue;
                # at this point, we've found the byte we're looking for
                recoveredPlaintext = x.to_bytes(1, byteorder='big') + recoveredPlaintext;
                # move to next value of i
                break;
            # not the right x, iterate.
            # if we've gone through all the x values, there's an error
            if (x == 255):
                print("ERROR finding good padding");
        # end for x in range(256)
    # end for i in range(len(rawBlock))
    return recoveredPlaintext


def recoverPlaintext():
    targetCipher, iv = encryptString();
    targetBlocks = chunks(targetCipher, 16);
    plaintext = b'';
    for i in range(len(targetBlocks)):
        plaintext += recoverBlock(targetBlocks[i], iv);
        iv = targetBlocks[i];
    return plaintext;



if __name__ == "__main__":
    rawPlaintext = recoverPlaintext();
    print(b'Raw Plaintext: ' + rawPlaintext);
    unpaddedPlaintext = removePKCS7Padding(rawPlaintext);
    print(b'Padding removed: ' + unpaddedPlaintext);
    
    
