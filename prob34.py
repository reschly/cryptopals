#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 34
#  Implement a MITM key-fixing attack on Diffie-Hellman with
# parameter injection
from prob33 import group5_p, group5_g, mypow, secretToKeys, intToBytes
from random import randrange
from prob10 import aes_cbc_enc, aes_cbc_dec
from prob9 import addPKCS7Padding
from prob11 import generateAESKey
from prob13 import removePKCS7Padding


# Use the code you just worked out to build a protocol and an
# "echo" bot. You don't actually have to do the network part of this
# if you don't want; just simulate that. The protocol is:

# A->B            Send "p", "g", "A"
def message1():
    a = randrange(2, group5_p-2);
    A = mypow(group5_g, a, group5_p);
    state = { "p" : group5_p, "g" : group5_g, 
           "a" : a, "A" : A };
    return state;

# B->A            Send "B"
def message2(state):
    b = randrange(2, state["p"]-2);
    B = mypow(state["g"], b, state["p"]);
    state["b"] = b;
    state["B"] = B;
    return state;
# A->B            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
def message3(state):
    a_shared = mypow(state["B"], state["a"], state["p"]);
    state["a_cipherkey"], state["a_mackey"] = secretToKeys(intToBytes(a_shared));
    a_iv = generateAESKey();
    message = b"mary had a little lamb"
    a_cipher = aes_cbc_enc(addPKCS7Padding(message, 16), state["a_cipherkey"], a_iv);
    state["a_cipher"] = a_cipher;
    state["a_iv"] = a_iv;
    return state;
# B->A            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
def message4(state):
    b_shared = mypow(state["A"], state["b"], state["p"]);
    state["b_cipherkey"], state["b_mackey"] = secretToKeys(intToBytes(b_shared));
    b_iv = generateAESKey();
    received_message = removePKCS7Padding(aes_cbc_dec(state["a_cipher"], state["b_cipherkey"], state["a_iv"]));
    b_cipher = aes_cbc_enc(addPKCS7Padding(received_message, 16), state["b_cipherkey"], b_iv);
    state["b_cipher"] = b_cipher;
    state["b_iv"] = b_iv;
    state["b_received_plain"] = received_message;
    return state;
def final(state):
    state["a_received_plain"] = removePKCS7Padding(aes_cbc_dec(state["b_cipher"], state["a_cipherkey"], state["b_iv"]));
    return state;
def check_protocol(state):
    assert(state["a_received_plain"] == state["b_received_plain"]);


# Now implement the following MITM attack:

# A->M            Send "p", "g", "A"
# M->B            Send "p", "g", "p"
def message1_5(state):
    state["A"] = state["p"];
    return state;

# B->M            Send "B"
# M->A            Send "p"
def message2_5(state):
    state["B"] = state["p"]
    return state;
# A->M            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# M->B            Relay that to B
def message3_5(state):
    # A's secret is p^a = (g^1) ^ a = A
    cipherkey, mackey = secretToKeys(intToBytes(state["A"]))
    plain = removePKCS7Padding(aes_cbc_dec(state["a_cipher"], cipherkey, state["a_iv"]));
    # B's secret is p^b = (g^1)^b = B
    cipherkey, mackey = secretToKeys(intToBytes(state["B"]))
    cipher = aes_cbc_enc(addPKCS7Padding(plain, 16), cipherkey, state["a_iv"]);
    state["a_cipher"] = cipher;
    return state;
# B->M            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
# M->A            Relay that to A
def message4_5(state):
    # message 3.5 in the opposite order
    cipherkey, mackey = secretToKeys(intToBytes(state["B"]))
    plain = removePKCS7Padding(aes_cbc_dec(state["b_cipher"], cipherkey, state["b_iv"]));
    cipherkey, mackey = secretToKeys(intToBytes(state["A"]))
    cipher = aes_cbc_enc(addPKCS7Padding(plain, 16), cipherkey, state["b_iv"]);
    state["b_cipher"] = cipher;
    return state;
    
# M should be able to decrypt the messages. "A" and "B" in the protocol
# --- the public keys, over the wire --- have been swapped out with "p".
# Do the DH math on this quickly to see what that does to the
# predictability of the key.

# Decrypt the messages from M's vantage point as they go by.
def testParameterInjection():
    state = message1();
    state = message1_5(state);
    state = message2(state);
    state = message2_5(state);
    state = message3(state);
    state = message3_5(state);
    state = message4(state);
    state = message4_5(state);
    final(state);
    check_protocol(state);

if __name__ == "__main__":
    testParameterInjection();
    # getting here means assert() succeeded
    print("Problem 34 success");

'''Note that you don't actually have to inject bogus parameters to make
this attack work; you could just generate Ma, MA, Mb, and MB as valid
DH parameters to do a generic MITM attack. But do the parameter
injection attack; it's going to come up again.'''