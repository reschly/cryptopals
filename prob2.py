#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 2
# Write a function that takes two equal-length buffers and produces
# their XOR sum.
# For example:
# hex_xor(1c0111001f010100061a024b53535009181c, 686974207468652062756c6c277320657965) = 
# 746865206b696420646f6e277420706c6179

from prob1 import hexToRaw, rawToHex

#def hexToRaw(s):
#    return binascii.unhexlify(s);
#def rawToHex(raw):
#    return binascii.hexlify(bytes(raw, 'UTF-8'));


def hex_xor(hex1, hex2):
    if (len(hex1) != len(hex2)):
        return '';
    raw1 = hexToRaw(hex1);
    raw2 = hexToRaw(hex2);
    rawresult = '';
    for i in range(0, len(raw1)):
        rawresult += chr(raw1[i] ^ raw2[i]);
#    rawresult = raw1 ^ raw2;
    return rawToHex(rawresult);

def test2():
    input1 = b'1c0111001f010100061a024b53535009181c';
    input2 = b'686974207468652062756c6c277320657965';
    expected = b'746865206b696420646f6e277420706c6179';
    result = hex_xor(input1, input2);
    if (result == expected):
        return True;
    else:
        print('Expected: ', expected);
        print("Result:   ", result);
        return False;

if __name__ == "__main__":
    if (test2()):
        print("Program 2 success");
    else:
        print("Failure");
    