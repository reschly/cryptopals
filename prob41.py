#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 41
# Implement Unpadded Message Recovery Oracle
from prob33 import mypow
from prob39 import generatePrime, invmod

# Imagine a web application, again with the Javascript encryption,
# taking RSA-encrypted messages which (again: Javascript) aren't padded
# before encryption at all.

# You can submit an arbitrary RSA blob and the server will return
# plaintext. But you can't submit the same message twice: let's say the
# server keeps hashes of previous messages for some liveness interval,
# and that the message has an embedded timestamp:

#  {
#    time: 1356304276,
#    social: '555-55-5555',
#  }

# You'd like to capture other people's messages and use the server to
# decrypt them. But when you try, the server takes the hash of the
# ciphertext and uses it to reject the request. Any bit you flip in the
# ciphertext irrevocably scrambles the decryption.

# This turns out to be trivially breakable:
def generate_rsa_key(bits, e=65537):
    result = { "e" : e }
    p = (e+1)
    q = (e+1)
    while ((p % e) == 1):
        p = generatePrime(bits//2);
    while ((q%e) == 1):
        q = generatePrime(bits//2);
    result["p"] = p;
    result["q"] = q;
    result["N"] = p*q;
    result["d"] = invmod(e, (p-1)*(q-1));
    return result;


# * Capture the ciphertext C
def capture_ciphertext(message, modulus, e):
    return mypow(message, e, modulus);

def decrypt_cipher(cipher, rsaparams):
    return mypow(cipher, rsaparams['d'], rsaparams['N'])

# * Let N and E be the public modulus and exponent respectively

# * Let S be a random number > 1 mod N. Doesn't matter what.

# * C' = ((S**E mod N) * C) mod N

# * Submit C', which appears totally different from C, to the server,
#  recovering P', which appears totally different from P

#         P'
#   P = -----  mod N
#         S

# Oops!

# (Remember: you don't simply divide mod N; you multiply by the
# multiplicative inverse mod N.)

# Implement that attack.
def do_unpadded_rsa_attack():
    rsaparams = generate_rsa_key(2048);
    e = rsaparams['e']
    N = rsaparams['N']
    messageBytes = b'Oh captain my captain'
    messageInt = int.from_bytes(messageBytes, byteorder="big")
    capturedCipher = capture_ciphertext(messageInt, N, e);
    
    S = 8675309
    C_prime = (mypow(S, e, N) * capturedCipher) % N;
    P_prime = decrypt_cipher(C_prime, rsaparams);
    plain = (P_prime * invmod(S, N)) % N;
    assert(plain == messageInt);
    
if __name__ == "__main__":
    do_unpadded_rsa_attack();
    print("problem 41 success");
    