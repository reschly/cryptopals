#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 22
# "Crack" An MT19937 Seed

from prob21 import MT19937
from time import time
from random import randint

# Make sure your MT19937 accepts an integer seed value. Test it (verify
# that you're getting the same sequence of outputs given a seed).
def test_mt():
    mt1 = MT19937(8675309);
    mt2 = MT19937(8675309);
    for i in range(10000):
        if (mt1.extract_number() != mt2.extract_number()):
            print("Fail MT test!");

# I do these exercises around 10pm.  I'm not waiting for actual time to pass
initialTime = int(time());
delay1 = randint(40, 1000);
delay2 = randint(40, 1000);

# Write a routine that performs the following operation:
def randFromTime():
# * Seeds the RNG with the current Unix timestamp
    mt = MT19937(initialTime + delay1);
#* Returns the first 32 bit output of the RNG.
    return mt.extract_number();

# From the 32 bit RNG output, discover the seed.

def recoverSeed(output, timeNow):
    # we're pretty sure that the seed is in the range (timeNow - 2005, timeNow)
    # but we'll push the range check out to 10000 just for fun
    for i in range(10000):
        #guess seed
        mt = MT19937(timeNow - i);
        #check seed
        if (output == mt.extract_number()):
            print("Seed: ", timeNow - i);
            return i;
    print("Failed to recover seed");
    return -1;


if __name__ == "__main__":
    test_mt();
    # get random output
    randOutput = randFromTime();
    # try to recover the seed at the "current" time
    recoverSeed(randOutput, int(time()) + delay1 + delay2);
    