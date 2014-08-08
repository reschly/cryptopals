#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 6
# Break repeating-key XOR
# The buffer at the following location:
# https://gist.github.com/3132752
# is base64-encoded repeating-key XOR. Break it.
# Here's how:
#
# a. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
#
# b. Write a function to compute the edit distance/Hamming 
# distance between two strings. The Hamming distance is just the number of
# differing bits. The distance between:
#
# this is a test
# and:
# wokka wokka!!!
# is 37.
#
# c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
# SECOND KEYSIZE worth of bytes, and find the edit distance between
# them. Normalize this result by dividing by KEYSIZE.
#
# d. The KEYSIZE with the smallest normalized edit distance is probably
# the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
# values. Or take 4 KEYSIZE blocks instead of 2 and average the
# distances.
#
# e. Now that you probably know the KEYSIZE: break the ciphertext into
# blocks of KEYSIZE length.
#
# f. Now transpose the blocks: make a block that is the first byte of
# every block, and a block that is the second byte of every block, and
# so on.
#
# g. Solve each block as if it was single-character XOR. You already
# have code to do this.
#
# e. For each block, the single-byte XOR key that produces the best
# looking histogram is the repeating-key XOR key byte for that
# block. Put them together and you have the key.

from prob2 import hex_xor
from prob1 import base64toHex, base64toRaw, rawToHexLUT, rawToHex, hexToRaw
from prob3 import tryKey;
from prob5 import repeating_hex_xor

hexBitCount = { '0':0, '1': 1, '2': 1, '3':2, '4': 1, '5': 2, '6': 2, '7':3, '8': 1, '9': 2, 
               'a': 2, 'b': 3, 'c': 2, 'd': 3, 'e': 3, 'f': 4,
               'A': 2, 'B': 3, 'C': 2, 'D': 3, 'E': 3, 'F': 4};


def hammingDistance(hex1, hex2):
    diff = hex_xor(hex1, hex2);
    #print(diff);
    result = 0;
    for c in diff:
        result += hexBitCount[chr(c)];
    return result;

def findKeySize(hexCipher, numblocks):
    bestKeySizes = [0,0,0];
    bestScores = [10000000.0,10000000.0,10000000.0];
    worstBestIndex = 0; # "best" score to be replaced next"
    
    for i in range(2,41):
        str1 = hexCipher[0:2*numblocks*i];
        str2 = hexCipher[2*numblocks*i:4*numblocks*i];
        diff = hammingDistance(str1, str2);
        score = (diff / float(numblocks * i));
        if (score < bestScores[worstBestIndex]):
            bestKeySizes[worstBestIndex] = i;
            bestScores[worstBestIndex] = score;
            worstBestIndex = 0;
            if (bestScores[1] > bestScores[0]):
                worstBestIndex = 1;
            if (bestScores[2] > bestScores[worstBestIndex]):
                worstBestIndex = 2;
    
    return bestKeySizes, bestScores;            
    
def splitCipher(rawCipher, numBlocks):
    splits = []
    for i in range(numBlocks):
        splits.append(rawCipher[i::numBlocks]);
    return splits;

def findKey(split):
    bestMg = 0.0;
    bestKey = 0;
    for i in range(256):
        mg, plain = tryKey(rawToHex(split), rawToHexLUT[i]);
        if (mg > bestMg):
            bestMg = mg;
            bestKey = i;
    return chr(bestKey);
        
b64cipher = "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";

if __name__ == "__main__":
    bestKeySizes, bestScores = findKeySize(base64toHex(b64cipher), 20);
    # print(bestKeySizes);
    # print(bestScores);
    # after running this with a bunch of different number of blocks, 29 always pops out.
    # I'm confident 29 is the right answer.
    splits = splitCipher(base64toRaw(b64cipher), 29);
    key = "";
    for s in splits:
        key += (findKey(s));
    print("Key: " + str(key));
    print("Plain: " + str(hexToRaw(repeating_hex_xor(base64toHex(b64cipher), rawToHex(key)))));
    
