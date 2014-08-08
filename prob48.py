#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 48
#  Bleichenbacher's PKCS 1.5 Padding Oracle (Complete)
from prob41 import generate_rsa_key
from prob33 import mypow
from prob47 import bb98_2a, bb98_2b, bb98_2c, bb98_3

# This is a continuation of challenge #47; it implements the complete
# BB'98 attack.

# Set yourself up the way you did in #47, but this time generate a 768
# bit modulus.

prob48_key = generate_rsa_key(768);
# ............ = 0x000102030405060708091011121314151617181920212223242526272829303100010203040506070809101112131415161718192021222324252627282930310001020304050607080910111213141516171819202122232425262728293031
prob48_message = 0x00029843216464613acd6546e3131eacd6634213659843216464613acd6546e3131eacd6634213659843216464613acd6546e3131eacd6634213659843216464613acd6546e3131eacd6634213659843216464613a0030313233343536373839

# To make the attack work with a realistic RSA keypair, you need to
# reproduce step 2b from the paper, and your implementation of Step 3
# needs to handle multiple ranges.
'''Note: I wrote step 2b for problem 47 when trying to debug.'''


# The full Bleichenbacher attack works basically like this:

# *       Starting from the smallest 's' that could possibly produce
#         a plaintext bigger than 2B, iteratively search for an 's' that
#         produces a conformant plaintext.

# *       For our known 's1' and 'n', solve m1=m0s1-rn (again: just a
#         definition of modular multiplication) for 'r', the number of
#         times we've wrapped the modulus.

#        'm0' and 'm1' are unknowns, but we know both are conformant
#        PKCS#1v1.5 plaintexts, and so are between [2B,3B].

#        We substitute the known bounds for both, leaving only 'r'
#        free, and solve for a range of possible 'r'  values. This
#        range should be small!

#*       Solve m1=m0s1-rn again but this time for 'm0', plugging in
#        each value of 'r' we generated in the last step. This gives
#        us new intervals to work with. Rule out any interval that
#        is outside 2B,3B.

#*       Repeat the process for successively higher values of 's'.
#        Eventually, this process will get us down to just one
#        interval, whereupon we're back to exercise #47.

#What happens when we get down to one interval is, we stop blindly
#incrementing 's'; instead, we start rapidly growing 'r' and backing it
#out to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or
#'m0'. So much algebra! Make your teenage son do it for you! *Note:
#does not work well in practice*

if __name__ == "__main__":
    cipher = mypow(prob48_message, prob48_key['e'], prob48_key['N']);
    s = bb98_2a(prob48_key, cipher);
    prev_intervals = [[2*prob48_key['B'], 3*prob48_key['B']-1]];
    prev_intervals = bb98_3(prev_intervals, prob48_key, s);
    while (True):
        #print("intervals: " , prev_intervals);
        if (len(prev_intervals) == 1):
            (a,b) = prev_intervals[0];
            if (a == b):
                print("Message: " + hex(a));
                break;
            r, s = bb98_2c(prev_intervals, s, prob48_key, cipher);
        else:
            s = bb98_2b(prob48_key, cipher, s)
        prev_intervals = bb98_3(prev_intervals, prob48_key, s);
    
    if (a == prob48_message):
        print("problem 48 success");
    else:
        print("Wrong answer");  

