#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 23
# Clone An MT19937 RNG From Its Output
from prob21 import MT19937

# The internal state of MT19937 consists of 624 32 bit integers.

# For each batch of 624 outputs, MT permutes that internal state. By
# permuting state regularly, MT19937 achieves a period of 2**19937,
# which is Big.

# Each time MT19937 is tapped, an element of its internal state is
# subjected to a tempering function that diffuses bits through the
# result.

# The tempering function is invertible; you can write an "untemper"
# function that takes an MT19937 output and transforms it back into the
# corresponding element of the MT19937 state array.

# To invert the temper transform, apply the inverse of each of the
# operations in the temper transform in reverse order. There are two
# kinds of operations in the temper transform each applied twice; one is
# an XOR against a right-shifted value, and the other is an XOR against
# a left-shifted value AND'd with a magic number. So you'll need code to
# invert the "right" and the "left" operation.

# so I can test w/o instantiating an MT:
def temper(y):
    y = y ^ (y >> 11);
    y = y ^ ((y << 7) & 0x9d2c5680);
    y = y ^ ((y << 15) & 0xefc60000);
    y = y ^ (y >> 18);
    return y;

def untemper(y):
    # y := y3 xor (right shift by 18 bits(y3))
    # thus, high 18 bits(y3) = high 18 bits (y)
    y3 = (y & 0xffffc000);
    # low 14 = (high 14 >> 18) ^ low 14
    y3 |= ((y >> 18) ^ (y&0x3fff));
    # y3 := y2 xor (left shift by 15 bits(y2) and (4022730752)) // 0xefc60000
    # bits not masked by xor carry over from y2 to y3 and vice-versa
    y2 = (y3 & 0x1039ffff);
    # now know the low 17 bits of y2, so strip off the xor
    y2 |= ((y3 ^ ((y2 << 15) & 0xefc60000)) & 0xfffe0000);
    # y2 := y1 xor (left shift by 7 bits(y1) and (2636928640)) // 0x9d2c5680
    # Bits 0-6 carry over:
    y1 = y2 & 0x7f;
    # reover bits 7-13 by masking off xor of 0-6
    y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 7));
    # recover bits 14-20 by maksing off xor of 7-13
    y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 14));
    # recover bits 21-27 by masking off xor of 14-20
    y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 21));
    # recover bits 28-31 by masking off xor if bits 21-24
    y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & 0xf0000000);
    # y1 := y0 xor (right shift by 11 bits(y0))
    # high 11 bits carry over:
    y0 = (y1 & 0xffe00000);
    # recover next 11 bits
    y0 |= (((y0 >> 11) ^ y1) & 0x001ffc00);
    # recover last 10
    y0 |= (((y0 >> 11) ^ y1) & 0x3ff);

    return y0;

def temperTest():
    for i in [0, 1, 12345, 8675309, 0xffffffff]:
        forward = temper(i);
        backward = untemper(forward);
        if (backward != i):
            raise Exception("Untemper error");
    print("untemper test success");


# Once you have "untemper" working, create a new MT19937 generator, tap
# it for 624 outputs, untemper each of them to recreate the state of the
# generator, and splice that state into a new instance of the MT19937
# generator.
def cloneMT(dolly):
    clone = MT19937(0);
    # Note that the call to extract_number() is going to 
    # call dolly.generate_numbers(), mucking with dolly's MT values
    # before we get to untemper
    # thus, the returned clone will be identical to dolly's state after
    # this function is finished, not before
    for i in range(624):
        clone.MT[i] = untemper(dolly.extract_number());
    return clone;


# How would you modify MT19937 to make this attack hard? What would
# happen if you subjected each tempered output to a cryptographic hash?

'''The root problem is that one can connect an output value to PRNG state.
Preventing an attacker from working backwards (output = sha256(y)) would prevent that...
However, given that (y) is 32 bits, the attacker could build a 4-billion-entry table to invert
such outputs.  A better solution would be to use, say, the last 4 bytes of MT has an AES key,
and then have (output = AES(y|000...00, key)).  The keyspace prevents the attacker from 
building the table.'''



if __name__ == "__main__":
    temperTest();
    dolly = MT19937(8675309);
    clone = cloneMT(dolly);
    for i in range(10000):
        if (dolly.extract_number() != clone.extract_number()):
            raise Exception("Clone failed");
    print("Clone succeeded");