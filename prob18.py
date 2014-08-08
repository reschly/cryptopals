#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 18
# 18. Implement CTR mode

from struct import unpack, pack
from prob8 import chunks
from prob10 import aes_ecb_enc
from prob1 import base64toRaw

#The string:
#    L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
# decrypts to something approximating English in CTR mode, which is an
# AES block cipher mode that turns AES into a stream cipher, with the
# following parameters:
#          key=YELLOW SUBMARINE
#          nonce=0
#          format=64 bit unsigned little endian nonce,
#                 64 bit little endian block count (byte count / 16)

# For instance, for the first 16 bytes of a message with these
# parameters:
#    keystream = AES("YELLOW SUBMARINE",
#                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
# for the next 16 bytes:
#    keystream = AES("YELLOW SUBMARINE",
#                   "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
# and then:
#    keystream = AES("YELLOW SUBMARINE",
#                   "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

def incrementIV(rawIV):
    nonce = rawIV[0:8];
    LEcounter = rawIV[8:16];
    counter = unpack('<Q', LEcounter)[0];
    counter += 1;
    counter = (counter % 0x10000000000000000);
    LEcounter = pack('<Q', counter);
    return (nonce + LEcounter);

def aes_ctr(rawInput, rawKey, rawIV):
    inputBlocks = chunks(rawInput, 16);
    rawOutput = b'';
    for block in inputBlocks:
        keyStream = aes_ecb_enc(rawIV, rawKey);
        rawOutput += raw_xor(keyStream, block);
        rawIV = incrementIV(rawIV);
    return rawOutput;

def raw_xor(in1, in2):
    length = min(len(in1), len(in2));
    result = [(in1[i] ^ in2[i]).to_bytes(1, byteorder='big') for i in range(length)];
    return b''.join(result);

def test18():
    rawCipher = base64toRaw(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==');
    rawKey = b'YELLOW SUBMARINE';
    rawIV = b'\x00' * 16;
    print(aes_ctr(rawCipher, rawKey, rawIV));
    
if __name__ == "__main__":
    test18();