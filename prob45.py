#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 45
# DSA Parameter Tampering
from prob43 import prob43_p, prob43_q, prob43_g
from prob33 import mypow
from prob39 import invmod

# Take your DSA code from the previous exercise. Imagine it as part of
# an algorithm in which the client was allowed to propose domain
# parameters (the p and q moduli, and the g generator).

# This would be bad, because attackers could trick victims into accepting
# bad parameters. Vaudenay gave two examples of bad generator
# parameters: generators that were 0 mod p, and generators that were 1
# mod p.

# Use the parameters from the previous exercise, but substitute 0 for
# "g". Generate a signature. You will notice something bad. Verify the
# signature. Now verify any other signature, for any other string.

'''If g is 0, then both y (g^x) and r (g^k) are 0, but step 3 in 
the signing process (by wikipedia's instructions) are "if r is 0, 
choose a different k", thus creating an infinite loop.

If we ignore that step, then:
r = 0
s = inv(k)*Hash(message),
and thus we can recover (k) as we know both (s) and (message), 
and thus we can recover the private key.

To verify, step 1 (wikipedia, again) is to reject the signature
if r is not in the range (0,q).  Again, we must ignore this step.
If we do:
v = g^u1 * y^u2 = 0*(other stuff) = 0 = r, thus all signatures validate...
'''

prob45_p = prob43_p
prob45_q = prob43_q
prob45_g0 = 0

def do_dsa_g0(message_hash):
    x = 8675309;
    k = 24601;
    y = mypow(prob45_g0, x, prob45_p);
    r = mypow(prob45_g0, k, prob45_p) % prob45_q;
    s = (invmod(k, prob45_p) * (message_hash + x*r)) % prob45_q;
    return (y,r,s)

def validate_dsa_g0(y, r, s, message_hash):
    w = invmod(s, prob45_q);
    u1 = (message_hash * w) % prob45_q;
    u2 = (r*w) % prob45_q;
    v = (mypow(prob45_g0, u1, prob43_p) * mypow(y, u2, prob45_p) % prob45_p) % prob45_q
    return v == r;

def demo_dsa_g0():
    message_hash = 0x0102030405060708091011121314151617181920
    (y, r, s) = do_dsa_g0(message_hash);
    assert(r == 0);
    assert(validate_dsa_g0(y, r, s, message_hash));
    # change public key, s -- still works
    assert(validate_dsa_g0(13, 0, 23423423432, message_hash));
    # change hash as well -- still works
    assert(validate_dsa_g0(32432423, 0, 342423432423, 0x3daf05ce546d1));


# Now, try (p+1) as "g". With this "g", you can generate a magic
# signature s, r for any DSA public key that will validate against any
# string. For arbitrary z:

#    r = ((y**z) % p) % q

#          r
#    s =  --- % q
#          z

prob45_g1_x = 8675309
prob45_g1_y = mypow(prob43_g, prob45_g1_x, prob43_p) # key generation uses legit params
prob45_g1 = (prob43_p + 1)
prob45_g1_r = prob45_g1_y %  prob45_q # set z to 1
prob45_gr_s = prob45_g1_r # set z to 1


# Sign "Hello, world". And "Goodbye, world".
''' Just need to validate (r,s) as valid'''

def validate_dsa_g1(y, r, s, message_hash):
    w = invmod(s, prob45_q);
    u1 = (message_hash * w) % prob45_q;
    u2 = (r*w) % prob45_q;
    v = (mypow(prob45_g1, u1, prob43_p) * mypow(y, u2, prob45_p) % prob45_p) % prob45_q
    return v == r;

def demo_dsa_g1():
    hash1 = 0xe02aa1b106d5c7c6a98def2b13005d5b84fd8dc8 #sha1(b'Hello, world')
    hash2 = 0xdc519a4510e5e848e1f77da409fa1410c84d43fb #sha1(b'Goodbye, world')
    assert(validate_dsa_g1(prob45_g1_r, prob45_g1_r, prob45_gr_s, hash1));
    assert(validate_dsa_g1(prob45_g1_r, prob45_g1_r, prob45_gr_s, hash2));
    
if __name__ == "__main__":
    demo_dsa_g0();
    demo_dsa_g1();
    print("Problem 45 success");
