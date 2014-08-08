#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 5
# Write the code to encrypt the string:
#  Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal
# Under the key "ICE", using repeating-key XOR. It should come out to:
#  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
# Encrypt a bunch of stuff using your repeating-key XOR function. Get a feel for it.

from prob1 import rawToHex;
from prob2 import hex_xor

def repeating_hex_xor(hex1, hex2):
    if (len(hex1) < len(hex2)):
        shorter = hex1
        longer = hex2;
    else:
        shorter = hex2;
        longer = hex1;
    shorter *= int(1 + (len(longer)/len(shorter)));
    shorter = shorter[:len(longer)];
    return hex_xor(shorter, longer);

def test5():
    plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    key = "ICE";
    cipher = repeating_hex_xor(rawToHex(plain), rawToHex(key));
    expected = b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f';
    if (str(expected) == str(cipher)):
        return True;
    print("Expected: " + str(expected));
    print("Cipher  : " + str(cipher));
    return False;

if __name__ == "__main__":
    if (test5()):
        print("Program 5 success");
    else:
        print("Failure");
    
