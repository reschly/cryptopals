#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 37
# Break SRP with a zero key
from prob36 import SRP_p, SRP_g, SRP_k, SRP_step1, SRP_validate, SRP_step7,\
    SRP_step6, SRP_step5, SRP_step4, SRP_step3, SRP_step2
from prob33 import intToBytes
from hashlib import sha256
from random import randrange

# Get your SRP working in an actual client-server setting. "Log in" with
# a valid password using the protocol.
def run_SRP():
    state = { "p" : SRP_p, 
             "g" : SRP_g,
             "k" : SRP_k,
             "I" : b"matasano_prob37@reschly.com",
             "P" : b'GANDALF THE GREY'}
    state = SRP_step1(state);
    state = SRP_step2(state);
    state = SRP_step3(state);
    state = SRP_step4(state);
    state = SRP_step5(state);
    state = SRP_step6(state);
    state = SRP_step7(state);
    assert(SRP_validate(state));

# Now log in without your password by having the client send 0 as its
# "A" value. What does this to the "S" value that both sides compute?
''' If A = 0, the server calculates:
    S = (A * v**u) ** b % N = 
      = (0*something)^something mod N = 0
    The client, being the evil one, just sets S to 0
'''
def client0_SRP():
    state = { "p" : SRP_p, 
             "g" : SRP_g,
             "k" : SRP_k,
             "I" : b"matasano_prob37@reschly.com",
             "P" : b'GANDALF THE GREY'}
    state = SRP_step1(state);
    state = SRP_step2(state);
    state["A"] = 0;
    state = SRP_step3(state);
    state = SRP_step4(state);
    #state = SRP_step5(state);
    '''Step 5 is the one in the client would use the password.
    This client doesn't know the password, but instead does:'''
    state["C_K"] = sha256(intToBytes(0)).digest();
    state = SRP_step6(state);
    state = SRP_step7(state);
    assert(SRP_validate(state));

# Now log in without your password by having the client send N, N*2, &c.
''' If A = k*N, the server calculates:
    S = (A * v**u) ** b % N = 
      = (k*N*something)^something mod N = 0 mod N
    again, the client, being the evil one, just sets S to 0
'''
def clientN_SRP():
    state = { "p" : SRP_p, 
             "g" : SRP_g,
             "k" : SRP_k,
             "I" : b"matasano_prob37@reschly.com",
             "P" : b'GANDALF THE GREY'}
    state = SRP_step1(state);
    state = SRP_step2(state);
    k = randrange(1, 30)
    state["A"] = k*SRP_p;
    state = SRP_step3(state);
    state = SRP_step4(state);
    #state = SRP_step5(state);
    '''Step 5 is the one in the client would use the password.
    This client doesn't know the password, but instead does:'''
    state["C_K"] = sha256(intToBytes(0)).digest();
    state = SRP_step6(state);
    state = SRP_step7(state);
    assert(SRP_validate(state));


if __name__ == "__main__":
    run_SRP();
    client0_SRP()
    clientN_SRP()
    print("Problem 37 success");