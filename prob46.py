#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 46
# Decrypt RSA From One-Bit Oracle
from prob41 import generate_rsa_key
from prob33 import mypow
from prob1 import base64toRaw

# This is a bit of a toy problem, but it's very helpful for
# understanding what RSA is doing (and also for why pure
# number-theoretic encryption is terrifying).

# Generate a 1024 bit RSA key pair.
prob46_key = generate_rsa_key(1024);

# Write an oracle function that uses the private key to answer the
# question "is the plaintext of this message even or odd" (is the last
# bit of the message 0 or 1). Imagine for instance a server that
# accepted RSA-encrypted messages and checked the parity of their
# decryption to validate them, and spat out an error if they were of the
# wrong parity.
def rsa_oracle_isodd(key, cipher):
    plain = mypow(cipher, key['d'], key['N']);
    return (plain & 1);

# Anyways: function returning true or false based on whether the
# decrypted plaintext was even or odd, and nothing else.

# Take the following string and un-Base64 it in your code (without
# looking at it!) and encrypt it to the public key, creating a
# ciphertext:

mystery_plain = int.from_bytes(base64toRaw('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='), byteorder='big');
mystery_cipher = mypow(mystery_plain, prob46_key['e'], prob46_key['N']);

# With your oracle function, you can trivially decrypt the message.

# Here's why:

# * RSA ciphertexts are just numbers. You can do trivial math on
#  them. You can for instance multiply a ciphertext by the
#  RSA-encryption of another number; the corresponding plaintext will
#  be the product of those two numbers.

# * If you double a ciphertext (multiply it by (2**e)%n), the resulting
#  plaintext will (obviously) be either even or odd.

# * If the plaintext after doubling is even, doubling the plaintext
#  DIDN'T WRAP THE MODULUS --- the modulus is a prime number. That
#  means the plaintext is less than half the modulus.

# You can repeatedly apply this heuristic, once per bit of the message,
# checking your oracle function each time.

# Your decryption function starts with bounds for the plaintext of [0,n].

# Each iteration of the decryption cuts the bounds in half; either the
# upper bound is reduced by half, or the lower bound is.

# After log2(n) iterations, you have the decryption of the message.

# Print the upper bound of the message as a string at each iteration;
# you'll see the message decrypt "hollywood style".

# Decrypt the string (after encrypting it to a hidden private key, duh) above.
def print_range(i, low, high):
    print(i, ": Plaintext in range [", low, ", ", high, "]");

def do_prob46(key, cipher):
    original_cipher = cipher;
    plain_min = 0;
    plain_max = key['N'] - 1;
    print_range(0, plain_min, plain_max);
    i = 0;

    while (int(plain_min) != int(plain_max)):
        cipher = (2**key['e'] * cipher) % key['N'];
        if rsa_oracle_isodd(key, cipher):
            # plaintext in upper half of range
            if (plain_max - plain_min == 1):
                plain_min = plain_max;
            plain_min += (plain_max - plain_min) // 2;
        else:
            # plaintext in the lower half
            if (plain_max - plain_min == 1):
                plain_max = plain_min;
            plain_max -= (plain_max - plain_min) // 2;
        i += 1;
        print_range(i, plain_min, plain_max)
        
    # This seems to have errors on one of the lower bits,
    # I suspect this is due to rounding errors when
    # bounding the range.  So instead of accepting the
    # answer found, try to encrypt answers within 
    # 4 of the "answwer", and see if they encrypt to 
    # the original cipher
    for i in range(-4, 5):
        this_cipher = mypow(plain_min + i, key['e'], key['N']);
        if (this_cipher == original_cipher):
            print("Plaintext: ", hex(plain_min + i));
            return;
    
    raise Exception;
    



if __name__ == "__main__":
    do_prob46(prob46_key, mystery_cipher);
    print("problem 46 success");