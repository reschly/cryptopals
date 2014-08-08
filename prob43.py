#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 43
# DSA Key Recovery From Nonce

from prob39 import invmod
from prob33 import mypow


prob43_p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

prob43_q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b;

prob43_g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291


# The DSA signing operation generates a random subkey "k". You know this
# because you implemented the DSA sign operation.

# This is the first and easier of two challenges regarding the DSA "k"
# subkey.

# Given a known "k", it's trivial to recover the DSA private key "x":

#       (s * k) - H(msg)
#   x = ----------------  mod q
#               r

# Do this a couple times to prove to yourself that you grok it. Capture
# it in a function of some sort.

def get_dsa_key_from_known_k(r, s, k, msg_hash, q=prob43_q):
    top = ((s*k) - msg_hash) % q;
    x = top * invmod(r, q);
    return x;

# Now then. I used the parameters above. I generated a keypair. My
# pubkey is:

prob43_y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

#I signed

#  For those that envy a MC it can be hazardous to your health
#  So be friendly, a matter of life and death, just like a etch-a-sketch

# (My SHA1 for this string was d2d0714f014a9784047eaeccf956520045c45265;
# I don't know what NIST wants you to do, but when I convert that hash
# to an integer I get 0xd2d0714f014a9784047eaeccf956520045c45265).
prob43_msg_hash = 0xd2d0714f014a9784047eaeccf956520045c45265

# I get:

prob43_r = 548099063082341131477253921760299949438196259240
prob43_s = 857042759984254168557880549501802188789837994940

# I signed this string with a broken implemention of DSA that generated
# "k" values between 0 and 2^16. What's my private key?

def recover_dsa_key():
    for k in range(65537):
        potential_x = get_dsa_key_from_known_k(prob43_r, prob43_s, k, prob43_msg_hash)
        if (mypow(prob43_g, potential_x, prob43_p) == prob43_y):
            return (potential_x, k);
    # failure if here
    raise Exception;


# Its SHA-1 fingerprint (after being converted to hex) is:
#  0954edd5e0afe5542a4adf012611a91912a3ec16
# Obviously, it also generates the same signature for that string.

if __name__ == "__main__":
    print("(x,k): ", recover_dsa_key());
    print("problem 43 success");