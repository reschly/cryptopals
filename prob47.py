#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 47
# Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
from prob33 import mypow
from prob41 import generate_rsa_key

# Read the paper. It describes a padding oracle attack on
# PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle
# you built earlier; it's an "adaptive chosen ciphertext attack", which
# means you start with a valid ciphertext and repeatedly corrupt it,
# bouncing the adulterated ciphertexts off the target to learn things
# about the original.

# This is a common flaw even in modern cryptosystems that use RSA.

# It's also the most fun you can have building a crypto attack. It
# involves 9th grade math, but also has you implementing an algorithm
# that is complex on par with finding a minimum cost spanning tree.

# The setup:
# 
# *       Build an oracle function, just like you did in the last exercise, but
#         have it check for plaintext[0] == 0 and plaintext[1] == 2.

def is_pkcs1_formatted(key, cipher):
    #
    plain = mypow(cipher, key['d'], key['N']);
    # check for 0
    if ((plain.bit_length() + 15) //8) != ((key['N'].bit_length() + 7)//8):
        return False;
    # hex(plain) will start '0x2' if the second by is either 0x20 or 0x02
    # if 02, then len(hex) will be odd
    if (len(hex(plain)) % 2) == 0:
        return False;
    if (hex(plain)[0:3] != '0x2'):
        return False;
    return True;

# *       Generate a 256 bit keypair (that is, p and q will each be 128 bit
#         primes), [n, e, d].
prob47_key = generate_rsa_key(256);

# *       Plug d and n into your oracle function.

# *       PKCS1.5-pad a short message, like "kick it, CC", and call it
#   "m". Encrypt to to get "c".
# ............ = 0x0001020304050607080910111213141516171819202122232425262728293031
prob47_message = 0x00029843216464613acd6546e3131eacd6634213650030313233343536373839

# Decrypt "c" using your padding oracle.

# For this challenge, we've used an untenably small RSA modulus (you
# could factor this keypair instantly). That's because this exercise
# targets a specific step in the Bleichenbacher paper --- Step 2c, which
# implements a fast, nearly O(log n) search for the plaintext.

# Things you want to keep in mind as you read the paper:

# *       RSA ciphertexts are just numbers.

# *       RSA is "homomorphic" with respect to multiplication, which
#   means you can multiply c * RSA(2) to get a c' that will
#         decrypt to plaintext * 2. This is mindbending but easy to
#        see if you play with it in code --- try multiplying
#   ciphertexts with the RSA encryptions of numbers so you know
#   you grok it.

#         What you need to grok for this challenge is that Bleichenbacher
#         uses multiplication on ciphertexts the way the CBC oracle uses
#         XORs of random blocks.

# *       A PKCS#1v1.5 conformant plaintext, one that starts with 00:02,
#         must be a number between 02:00:00...00 and 02:FF:FF..FF --- in
#         other words, 2B and 3B-1, where B is the bit size of the
#         modulus minus the first 16 bits. When you see 2B and 3B,
#         that's the idea the paper is playing with.

# To decrypt "c", you'll need Step 2a from the paper (the search for the
# first "s" that, when encrypted and multiplied with the ciphertext,
# produces a conformant plaintext), Step 2c, the fast O(log n) search,
# and Step 3.

def myfloor(a, b):
    res = (a // b);
    return res;
    
def myceil(a,b):
    res = (a // b);
    if (a % b):
        res += 1;
    return res;
    

def bb98_2a(key, c0):
    k = (key['N'].bit_length()+7)//8
    B = pow(2, 8*(k-2));
    key['B'] = B;
    s = myceil(key['N'], 3*B);
    cipher = (c0 * mypow(s, key['e'], key['N'])) % key['N'];
    while (not is_pkcs1_formatted(key, cipher)):
        s += 1;
        cipher = (c0 * mypow(s, key['e'], key['N'])) % key['N'];
        #print(s, hex(cipher))
    #print("Step 2a returning ", s)
    return s;

def bb98_2b(key, c0, prev_s):
    s = prev_s + 1;
    cipher = (c0 * mypow(s, key['e'], key['N'])) % key['N'];
    while (not is_pkcs1_formatted(key, cipher)):
        s += 1;
        cipher = (c0 * mypow(s, key['e'], key['N'])) % key['N'];
        #print(s, hex(cipher))
    #print("Step 2b returning ", s)
    return s;


def bb98_2c(intervals, s_prev, key, c0):
    assert(len(intervals) == 1);
    (a,b) = intervals[0];
    r = myceil(2*(b*s_prev - 2*key['B']), key['N']);
    s = myceil((2*key['B'] + r*key['N']), b);
    while (True):
        cipher = (c0 * mypow(s, key['e'], key['N'])) % key['N'];
        if (is_pkcs1_formatted(key, cipher)):
            return (r,s);
        s = s+1;
        if (s > myfloor(3*key['B'] + r*key['N'], a)):
            r += 1;
            s = myceil((2*key['B'] + r*key['N']), b);
    
    
def bb98_3(prev_intervals, key, s):
    intervals = [];
    for (a,b) in prev_intervals:
        #print("using %d, %d from prevoius interval" % (a,b))
        min_r = myceil(a*s - 3*key['B'] + 1, key['N']);
        max_r = myfloor(b*s - 2*key['B'], key['N']);
        for r in range(min_r, max_r+1):
            aa = myceil(2*key['B'] + r*key['N'], s);
            bb = myfloor(3*key['B'] - 1 + r*key['N'], s);
            #print ("step3: aa, bb: ", aa, bb);
            lower_bound = max(aa, a);
            upper_bound = min(bb, b);
            #print("step3: lower, upper: ", lower_bound, upper_bound)
            if (lower_bound > upper_bound):
                continue;
            #print("Appending %d, %d" %(lower_bound, upper_bound))
            #if (lower_bound <= prob47_message and prob47_message <= upper_bound):
                #print("Answer in range");
            #else:
                #print("ANSWER OUT OF RANGE!!!!");
            bb98_append(intervals, lower_bound, upper_bound);
    return intervals;
            
def bb98_append(intervals, lower_bound, upper_bound):
    '''Appends the new interval to the existing set of intervals,
    reducing any overlaps, ie (2,7),(5,9) reduces to (2,9)
    and (2,7), (3,5) reduces to (2,7)'''
    for i in range(len(intervals)):
        # Given (l1, u1),(l2,u2) we care about everything except:
        # (u1 < l2) or (u2 < l1)
        if (intervals[i][1] < lower_bound):
            continue;
        if (upper_bound < intervals[i][0]):
            continue;
        # we must have overlap, thus replace with lower_bound, upper_bound with
        # min,max of (intervals[i], upper, lower)
        lower_bound = min(intervals[i][0], intervals[i][1], lower_bound);
        upper_bound = max(intervals[i][0], intervals[i][1], upper_bound);
        # remove the overlapping interval from the set
        #print("removing index %d" % i);
        intervals.remove(i);
        # add the new interval
        bb98_append(intervals, lower_bound, upper_bound);
        return;
    # if we reach here, then no overlap found -- just add interval
    intervals.append([lower_bound, upper_bound]);

            

# Your Step 3 code is probably not going to need to handle multiple
# ranges.

# We recommend you just use the raw math from paper (check, check,
# double check your translation to code) and not spend too much time
# trying to grok how the math works.

if __name__ == "__main__":
    cipher = mypow(prob47_message, prob47_key['e'], prob47_key['N']);
    s = bb98_2a(prob47_key, cipher);
    prev_intervals = [[2*prob47_key['B'], 3*prob47_key['B']-1]];
    prev_intervals = bb98_3(prev_intervals, prob47_key, s);
    while (True):
        #print("intervals: " , prev_intervals);
        if (len(prev_intervals) == 1):
            (a,b) = prev_intervals[0];
            if (a == b):
                print("Message: " + hex(a));
                break;
            r, s = bb98_2c(prev_intervals, s, prob47_key, cipher);
        else:
            s = bb98_2b(prob47_key, cipher, s)
        prev_intervals = bb98_3(prev_intervals, prob47_key, s);
    
    if (a == prob47_message):
        print("problem 47 success");
    else:
        print("Wrong answer");    