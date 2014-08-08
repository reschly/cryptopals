#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 40
# Implement an E=3 RSA Broadcast attack
from prob39 import egcd, invmod, generatePrime
from prob33 import mypow

# Assume you're a Javascript programmer. That is, you're using a
# naive handrolled RSA to encrypt without padding.

# Assume you can be coerced into encrypting the same plaintext
# three times, under three different public keys. You can; it's
# happened.

# Then an attacker can trivially decrypt your message, by:

# 1. Capturing any 3 of the ciphertexts and their corresponding pubkeys

# 2. Using the CRT to solve for the number represented by the three
# ciphertexts (which are residues mod their respective pubkeys)

# 3. Taking the cube root of the resulting number

# The CRT says you can take any number and represent it as the
# combination of a series of residues mod a series of moduli. In the
# three-residue case, you have:

# following https://en.wikipedia.org/wiki/Chinese_remainder_theorem#A_constructive_algorithm_to_find_the_solution
def do_CRT(a_list, N_list):
    assert(len(a_list) >= 3);
    assert(len(N_list) >= 3);
    x = 0;
    N = N_list[0] * N_list[1] * N_list[2];
    for i in range(3):
        (r,s) = egcd(N_list[i], N//N_list[i]);
        e = s*N//N_list[i];
        x += a_list[i] * e;
    return (x % N);

def do_rsa_broadcast_attack(pubkeys, messages):
    result = do_CRT(messages, pubkeys);
    return pow(result, 1/3.0);


def generateModulus(size, e):
    p = e+1;
    q = e+1;
    while ((p%e) == 1):
        p = generatePrime(size//2);
    while ((q%e) == 1):
        q = generatePrime(size//2);
    return p*q;

if __name__ == "__main__":
    # test cases from wikipedia
    assert(do_CRT((2,3,2), (3,5,7)) == 23);
    assert(do_CRT((2,3,1), (3,4,5)) == 11);
    data = 0x040815162342
    pubkeys = [generateModulus(1024, 3), generateModulus(1024, 3), generateModulus(1024, 3)];
    messages = [mypow(data, 3, N) for N in pubkeys];
    recovered = do_rsa_broadcast_attack(pubkeys, messages);
    assert(data == round(recovered));
    print("problem 40 success");
    
