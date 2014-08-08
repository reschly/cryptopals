#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 44
# DSA Nonce Recovery From Repeated Nonce
from prob43 import prob43_q, get_dsa_key_from_known_k
from prob39 import invmod

# At the following URL, find a collection of DSA-signed messages:

#  https://gist.github.com/anonymous/f83e6b6e6889f2e8b7ff

# (NB: each msg has a trailing space.)

# These were signed under the following pubkey:

prob44_y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

#(using the same domain parameters as the previous exercise)

# It should not be hard to find the messages for which we have
# accidentally used a repeated "k". Given a pair of such messages, you
# can discover the "k" we used with the following formula:

prob44_s1 = 1267396447369736888040262262183731677867615804316
prob44_r1 = 1105520928110492191417703162650245113664610474875
prob44_m1 = 0xa4db3de27e2db3e5ef085ced2bced91b82e0df19

prob44_s2 = 1021643638653719618255840562522049391608552714967
prob44_r2 = 1105520928110492191417703162650245113664610474875
prob44_m2 = 0xd22804c4899b522b23eda34d2137cd8cc22b9ce8

#           (m1 - m2)
#       k = --------- mod q
#           (s1 - s2)

def recover_dsa_k(hash1, hash2, r1, s1, r2, s2, q=prob43_q):
    top = (hash1 - hash2) % q;
    k = top * invmod((s1 - s2)%q, q);
    return k;



#Remember all this math is mod q; s2 may be larger than s1, for
# instance, which isn't a problem if you're doing the subtraction mod
#q. If you're like me, you'll definitely lose an hour to forgetting a
#paren or a mod q. (And don't forget that modular inverse function!)

#What's my private key? Its SHA-1 (from hex) is:

#     ca8f6f7c66fa362d40760d135b763eb8527d3d52

if __name__ == "__main__":
    k = recover_dsa_k(prob44_m1, prob44_m2, prob44_r1, prob44_s1, prob44_r2, prob44_s2);
    x1 = get_dsa_key_from_known_k(prob44_r1, prob44_s1, k, prob44_m1);
    x2 = get_dsa_key_from_known_k(prob44_r1, prob44_s1, k, prob44_m1);
    assert(x1 == x2);
    print("x = ", x1);
    print("problem 44 success");