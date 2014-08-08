#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 39
# Implement RSA

# There are two annoying things about implementing RSA. Both of them
# involve key generation; the actual encryption/decryption in RSA is
# trivial.

# First, you need to generate random primes. You can't just agree on a
# prime ahead of time, like you do in DH. You can write this algorithm
# yourself, but I just cheat and use OpenSSL's BN library to do the
# work.

from Crypto.Util.number import getPrime
from prob33 import mypow
from prob1 import rawToHex, hexToRaw

def generatePrime(bits):
    return getPrime(bits);
    
    
# The second is that you need an "invmod" operation (the multiplicative
# inverse), which is not an operation that is wired into your
# language. The algorithm is just a couple lines, but I always lose an
# hour getting it to work.

# I recommend you not bother with primegen, but do take the time to get
# your own EGCD and invmod algorithm working.

'''From https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Recursive_method_2

Returns (x,y) such that (ax + by) = gcd(a,b)'''
def egcd(a, b):
    if b == 0:
        return (1, 0)
    else:
        q = a // b;
        r = a % b;
        (s, t) = egcd(b, r)
        return (t, s - q * t)

# Returns a^-1 mod N
def invmod(a, N):
    # ax + by = 1:
    # ax - 1 = by
    # ax - 1 = 0 mod b
    # ax = 1 mod b
    # x is the inverse of a mod b
    (x, y) = egcd(a, N);
    return x % N;

# Now:

# - Generate 2 random primes. We'll use small numbers to start, so you
# can just pick them out of a prime table. Call them "p" and "q".

def rsa_demo1():
    p = 71;
    q = 77;
# - Let n be p * q. Your RSA math is modulo n.
    N = p*q;
# - Let et be (p-1)*(q-1) (the "totient"). You need this value only for
#  keygen.
    et = (p-1)*(q-1);
# - Let e be 3.
    e = 3;
    assert((et%e) != 0); #sufficient given a prime e
#- Compute d = invmod(e, et). invmod(17, 3120) is 2753.
    d = invmod(e,et)
# Your public key is [e, n]. Your private key is [d, n].
#To encrypt: c = m**e%n. To decrypt: m = c**d%n
#Test this out with a number, like "42".
    message = 42;
    encrypted = mypow(message, e, N);
    decrypted = mypow(encrypted, d, N);
    assert(message == decrypted);
    

#Repeat with bignum primes (keep e=3).
def rsa_demo2():
    e = 3;
    p = 4;
    q = 4;
    while ((p % e) == 1):
        p = generatePrime(1024);
    while ((q % e) == 1):
        q = generatePrime(1024);
    N = p*q;
    phi = (p-1)*(q-1);
    assert((phi%e) != 0);
    d = invmod(e, phi);
    message = 42;
    encrypted = mypow(message, e, N);
    decrypted = mypow(encrypted, d, N);
    assert(message == decrypted);
#Finally, to encrypt a string, do something cheesy, like convert the
#string to hex and put "0x" on the front of it to turn it into a
#number. The math cares not how stupidly you feed it strings.
    rawMessage = b'May the Force be with you'
    hexMessage = rawToHex(rawMessage);
    intMessage = int(hexMessage, 16);
    encrypted = mypow(intMessage, e, N);
    decrypted = mypow(encrypted, d, N);
    assert(intMessage == decrypted);
    assert(hexToRaw(hex(intMessage)[2:]) == rawMessage);
    
    
if __name__ == "__main__":
    rsa_demo1();
    rsa_demo2();
    print("Problem 39 success");
