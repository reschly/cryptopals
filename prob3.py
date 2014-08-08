#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 3
# The hex encoded string:
#  1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# has been XOR'd against a single character. Find the key, decrypt
# the message.

# Some of the 'magic' in this comes from a college crypto course
# That course used Stinson's Cryptography book, 3rd edition

from prob1 import hexToRaw, rawToHexLUT
from prob2 import hex_xor
import string

letterFrequency = {}
letterFrequency['A'] = .082;
letterFrequency['B'] = .015;
letterFrequency['C'] = .028;
letterFrequency['D'] = .043;
letterFrequency['E'] = .127;
letterFrequency['F'] = .022;
letterFrequency['G'] = .020;
letterFrequency['H'] = .061;
letterFrequency['I'] = .070;
letterFrequency['J'] = .002;
letterFrequency['K'] = .008;
letterFrequency['L'] = .040;
letterFrequency['M'] = .024;
letterFrequency['N'] = .067;
letterFrequency['O'] = .075;
letterFrequency['P'] = .019;
letterFrequency['Q'] = .001;
letterFrequency['R'] = .060;
letterFrequency['S'] = .063;
letterFrequency['T'] = .091;
letterFrequency['U'] = .028;
letterFrequency['V'] = .010;
letterFrequency['W'] = .023;
letterFrequency['X'] = .001;
letterFrequency['Y'] = .020;
letterFrequency['Z'] = .001;
letterFrequency[' '] = .200;

# See page 35, Stinson
def calculateMG(plain):
    counts = [];
    for i in range(256):
        counts.append(0);
    
    for i in range(len(plain)):
        if (plain[i] < 128):
            counts[ord(chr(plain[i]).upper())] += 1;    
    
    result = 0.0;
    for i in string.ascii_uppercase:
        result += letterFrequency[i]*counts[ord(i)];
    result += letterFrequency[' '] * counts[ord(' ')];
    result /= len(plain);
    return result;

def tryKey(cipher, key):
    fullkey = key * len(cipher);
    fullkey = fullkey[:len(cipher)];
    potential_plain = hex_xor(cipher, fullkey);
    return calculateMG(hexToRaw(potential_plain)), potential_plain;

def findGoodKeys(cipher):
    for i in range(256):
        mg, plain = tryKey(cipher, rawToHexLUT[i]);
        #print(str(i) + ": " + str(mg));
        if (mg > .050):
            print("potential key: 0x" + rawToHexLUT[i]);
            print("Potential hex(plain): " + str(plain).lstrip("b'").rstrip("'"));
            print("potential plaintext: " + str(hexToRaw(str(plain).lstrip("b'").rstrip("'"))).lstrip("b'").rstrip("'"));
        
        
if __name__ == "__main__":
    cip = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736';
    findGoodKeys(cip);
