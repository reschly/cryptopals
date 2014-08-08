#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 36
# Implement Secure Remote Password
from hashlib import sha256
from prob18 import raw_xor
from prob33 import group5_p, intToBytes, mypow
from random import randrange


# re-do of myhmac from problem 31 to support hashlib hashes
def myhmac(hash_function, message, key):
    blocksize = hash_function().block_size;
    if (len(key) > blocksize):
        key = hash_function(key).digest()
    if (len(key) < blocksize):
        key += (b'\x00' * (blocksize - len(key)));

    opad = raw_xor(b'\x5c' * blocksize, key);
    ipad = raw_xor(b'\x36' * blocksize, key);
    
    return hash_function(opad + hash_function(ipad + message).digest()).digest();


# To understand SRP, look at how you generate an AES key from DH; now,
# just observe you can do the "opposite" operation an generate a numeric
# parameter from a hash. Then:

# eplace A and B with C and S (client & server)

# C & S           Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
SRP_p = group5_p
SRP_g = 2;
SRP_k = 3;
I = b'matasano_prob36@reschly.com'
P = b'Bob The Builder!'


def SRP_init():
    state = { "p" : SRP_p, 
             "g" : SRP_g,
             "k" : SRP_k,
             "I" : I,
             "P" : P}
    return state;

# S               1. Generate salt as random integer
#                 2. Generate string xH=SHA256(salt|password)
#                 3. Convert xH to integer x somehow (put 0x on hexdigest)
#                 4. Generate v=g**x % N
#                5. Save everything but x, xH
def SRP_step1(state):
    salt = randrange(2, state["p"]-2);
    xH = sha256(intToBytes(salt) + state["P"]).hexdigest();
    x = int(xH, 16);
    v = mypow(state["g"], x, state["p"]);
    state["v"] = v;
    state["salt"] = salt;
    return state;

# C->S            Send I, A=g**a % N (a la Diffie Hellman)
def SRP_step2(state):
    state["a"] = randrange(2, state["p"]-2);
    state["A"] = mypow(state["g"], state["a"], state["p"]);
    return state;

# S->C            Send salt, B=kv + g**b % N
def SRP_step3(state):
    state["b"] = randrange(2, state["p"]-2);
    state["B"] = (state["k"] * state["v"] + mypow(state["g"], state["b"], state["p"]));
    return state;
    
# S, C            Compute string uH = SHA256(A|B), u = integer of uH
def SRP_step4(state):
    uH = sha256(intToBytes(state["A"]) + intToBytes(state["B"])).hexdigest();
    state["u"] = int(uH, 16);
    return state;

# C               1. Generate string xH=SHA256(salt|password)
#                 2. Convert xH to integer x somehow (put 0x on hexdigest)
#                 3. Generate S = (B - k * g**x)**(a + u * x) % N
#                 4. Generate K = SHA256(S)
def SRP_step5(state):
    xH = sha256(intToBytes(state["salt"]) + state["P"]).hexdigest();
    x = int(xH, 16);
    S = mypow((state["B"] - state["k"] * mypow(state["g"], x, state["p"])), (state["a"] + state["u"] * x), state["p"]);
    state["C_K"] = sha256(intToBytes(S)).digest();
    return state;

# S               1. Generate S = (A * v**u) ** b % N
#                 2. Generate K = SHA256(S)
def SRP_step6(state):
    S = mypow(state["A"] * mypow(state["v"], state["u"], state["p"]), state["b"], state["p"]);
    state["S_K"] = sha256(intToBytes(S)).digest();
    return state;
    
#C->S            Send HMAC-SHA256(K, salt)
def SRP_step7(state):
    state["challenge"] = myhmac(sha256, state["C_K"], intToBytes(state["salt"]));
    return state;
#S->C            Send "OK" if HMAC-SHA256(K, salt) validates
def SRP_validate(state):
    expected = myhmac(sha256, state["S_K"], intToBytes(state["salt"]));
    return expected == state["challenge"];


def test_srp():
    state = SRP_init();
    state = SRP_step1(state);
    state = SRP_step2(state);
    state = SRP_step3(state);
    state = SRP_step4(state);
    state = SRP_step5(state);
    state = SRP_step6(state);
    state = SRP_step7(state);
    return SRP_validate(state);

if __name__ == "__main__":
    if (test_srp()):
        print("Problem 36 success");
    else:
        print("Problem 36 failure");



'''You're going to want to do this at a REPL of some sort; it may take a
couple tries.

It doesn't matter how you go from integer to string or string to
integer (where things are going in or out of SHA256) as long as you do
it consistently. I tested by using the ASCII decimal representation of
integers as input to SHA256, and by converting the hexdigest to an
integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password
into the public keys. The server also takes an extra step to avoid storing
an easily crackable password-equivalent.'''