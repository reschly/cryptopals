#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 38
# Offline dictionary attack on simplified SRP
from prob36 import SRP_step1, SRP_step2, myhmac, SRP_init
from random import randrange
from prob33 import mypow, intToBytes
from hashlib import sha256

# S               x = SHA256(salt|password)
#                 v = g**x % n
simplified_SRP_step1 = SRP_step1;
# C->S            I, A = g**a % n
simplified_SRP_step2 = SRP_step2;
# S->C            salt, B = g**b % n, u = 128 bit random number
def simplified_SRP_step3(state):
    state["b"] = randrange(2, state["p"]-2);
    state["B"] = mypow(state["g"], state["b"], state["p"]);
    state["u"] = randrange(2, 2**128);
    return state;


# C               x = SHA256(salt|password)
#                 S = B**(a + ux) % n
#                 K = SHA256(S)
def simplified_SRP_step4(state):
    x = sha256(intToBytes(state["salt"]) + state["P"]).hexdigest();
    S = mypow(state["B"], state["a"] + state["u"] * int(x, 16), state["p"]);
    state["C_K"] = sha256(intToBytes(S)).digest();
    return state;
# S               S = (A * v ** u)**b % n
#                 K = SHA256(S)
def simplified_SRP_step5(state):
    S = mypow(state["A"] * mypow(state["v"], state["u"], state["p"]), state["b"], state["p"]);
    state["S_K"] = sha256(intToBytes(S)).digest();
    return state;
# C->S            Send HMAC-SHA256(K, salt)
def simplified_SRP_step6(state):
    state["challenge"]  = myhmac(sha256, state["C_K"], intToBytes(state["salt"]));
    return state;
#S->C            Send "OK" if HMAC-SHA256(K, salt) validates
def simplified_SRP_validate(state):
    expected = myhmac(sha256, state["S_K"], intToBytes(state["salt"]));
    return expected == state["challenge"];

# Note that in this protocol, the server's "B" parameter doesn't depend
# on the password (it's just a Diffie Hellman public key).

# Make sure the protocol works given a valid password.
def test_simplified_SRP():
    state = SRP_init();
    state = simplified_SRP_step1(state);
    state = simplified_SRP_step2(state);
    state = simplified_SRP_step3(state);
    state = simplified_SRP_step4(state);
    state = simplified_SRP_step5(state);
    state = simplified_SRP_step6(state);
    assert(simplified_SRP_validate(state));

# Now, run the protocol as a MITM attacker: pose as the server and use
# arbitrary values for b, B, u, and salt.

''' This will run the whole protocol, but to crack the password it won't
access any information the MITM wouldn't know, namely a, v, x or P'''
def run_simplified_SRP_MITM():
    state = SRP_init();
    state = simplified_SRP_step1(state);
    state = simplified_SRP_step2(state);
    state = simplified_SRP_step3(state);
    state = simplified_SRP_step4(state);
    state = simplified_SRP_step5(state);
    state = simplified_SRP_step6(state);
    return state;

# Crack the password from A's HMAC-SHA256(K, salt).
def try_simplified_SRP_password(state, guess):
    # hmac(K, salt) =
    # hmac(sha256(S), salt) =
    # hmac(sha256((A * v ** u)**b % n), salt) =
    # hmac(sha256((A * ((g**x)** u))**b % n), salt) =
    # hmac(sha256((A * ((g**SHA256(salt|password))** u))**b % n), salt) =
    # and now we're down to thinks we know (minus password)
    x = sha256(intToBytes(state["salt"]) + guess).hexdigest();
    v = mypow(state["g"], int(x, 16), state["p"]);
    v_u = mypow(v, state["u"], state["p"]);
    S = mypow(state["A"] * v_u, state["b"], state["p"]);
    mychal = myhmac(sha256, sha256(intToBytes(S)).digest(), intToBytes(state["salt"]));
    return mychal == state["challenge"];
    

def crack_simplified_SRP():
    state = run_simplified_SRP_MITM();
    pw_guess_list= [b'Thomas the tank engine', b'Dora the Explora', state["P"], b'Jake the Pirate']
    success = False;
    pw = None;
    for guess in pw_guess_list:
        if (try_simplified_SRP_password(state, guess)):
            success = True;
            pw = guess;
    assert(success);
    assert(pw == state["P"]);
    
    
    


if __name__ == "__main__":
    test_simplified_SRP();
    crack_simplified_SRP();
    print("problem 38 success");