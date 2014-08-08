#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 35
# Implement DH with negotiated groups, and break with malicious "g" parameters
from prob33 import group5_p, group5_g, mypow, secretToKeys, intToBytes
from random import randrange
from prob11 import generateAESKey
from prob10 import aes_cbc_enc, aes_cbc_dec
from prob9 import addPKCS7Padding
from prob13 import removePKCS7Padding
from prob15 import checkAndRemovePKCS7Padding

# A->B            Send "p", "g"
def message1():
    state = {};
    state["p"] = group5_p;
    state["g"] = group5_g
    return state;
# B->A            Send ACK
def message2(state):
    return state;
# A->B            Send "A"
def message3(state):
    state["a"] = randrange(2, group5_p-2);
    state["A"] = mypow(group5_g, state["a"], group5_p);
    return state;
# B->A            Send "B"
def message4(state):
    state["b"] = randrange(2, state["p"]-2)
    state["B"] = mypow(state["g"], state["b"], state["p"])
    return state;
# A->B            Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
def message5(state):
    message = b"Thomas, he's the cheeky one.  James is vain but lots of fun!";
    secret = mypow(state["B"], state["a"], group5_p);
    state["a_cipherkey"], state["a_mackey"] = secretToKeys(intToBytes(secret));
    state["a_iv"] = generateAESKey();
    state["a_cipher"] = aes_cbc_enc(addPKCS7Padding(message, 16), state["a_cipherkey"], state["a_iv"]);
    return state;
# B->A            Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
def message6(state):
    secret = mypow(state["A"], state["b"], state["p"]);
    state["b_cipherkey"], state["b_mackey"] = secretToKeys(intToBytes(secret));
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


# Do the MITM attack again, but play with "g". What happens with:
# g = 1
def message1_5_g1(state):
    state["g"] = 1;
    return state;
def message3_5_g1(state):
    state["A"] = 1;
    return state;
def check_protocol_g1(state):
    # B's public key is 1^b = 1.
    # A's secret is (1)^a = 1.
    # B's secret is (1)^b = 1
    # In this case, Mallory doesn't need to modify ciphers,
    # becasue A and B have the same shared secret.
    # But Mallory gets to know their messages (and potentially
    # inject her own)
    m_secret = 1;
    m_cipherkey, m_mackey = secretToKeys(intToBytes(m_secret));
    m_plain_a = removePKCS7Padding(aes_cbc_dec(state["a_cipher"], m_cipherkey, state["a_iv"]));
    m_plain_b = removePKCS7Padding(aes_cbc_dec(state["b_cipher"], m_cipherkey, state["b_iv"]));
    assert(m_plain_a == state["a_received_plain"]);
    assert(m_plain_b == state["b_received_plain"]);
    # check_protocol() takes care of the rest
def run_g1():
    state = message1();
    state = message1_5_g1(state);
    state = message2(state);
    state = message3(state);
    state = message3_5_g1(state);
    state = message4(state);
    state = message5(state);
    state = message6(state);
    state = final(state);
    check_protocol(state);
    check_protocol_g1(state);

# g = p
def message1_5_gp(state):
    state["g"] = state["p"];
    return state;
def message3_5_gp(state):
    state["A"] = state["p"];
    return state;
def check_protocol_gp(state):
    # B's public key is p^b mod p = 0.
    # A's secret is (0)^a = 1.
    # B's secret is (p^b) mod p = 0
    # Again, Mallory doesn't need to modify ciphers,
    # becasue A and B have the same shared secret.
    # But Mallory gets to know their messages (and potentially
    # inject her own)
    m_secret = 0;
    m_cipherkey, m_mackey = secretToKeys(intToBytes(m_secret));
    m_plain_a = removePKCS7Padding(aes_cbc_dec(state["a_cipher"], m_cipherkey, state["a_iv"]));
    m_plain_b = removePKCS7Padding(aes_cbc_dec(state["b_cipher"], m_cipherkey, state["b_iv"]));
    assert(m_plain_a == state["a_received_plain"]);
    assert(m_plain_b == state["b_received_plain"]);
    # check_protocol() takes care of the rest
def run_gp():
    state = message1();
    state = message1_5_gp(state);
    state = message2(state);
    state = message3(state);
    state = message3_5_gp(state);
    state = message4(state);
    state = message5(state);
    state = message6(state);
    state = final(state);
    check_protocol(state);
    check_protocol_gp(state);


# g = (p-1)
def message1_5_gp1(state):
    state["g"] = state["p"]-1;
    return state;
def message3_5_gp1(state):
    state["A"] = state["p"]-1;
    return state;
def message5_5_gp1(state):
    # (p-1) is essentially (-1)
    # B's secret is (-1)^b which is either (+1) or (-1) (and also B)
    # A's secret is (-1)^b^a, which is either (+1) or (-1),
    # but not necessarily the same as B's secret
    # thus, we may need to modify cipher
    # use CBC padding to check validity of key
    # check validity of cbc padding to determine which
    # B's secret 
    cipherkey_plus1, mackey_plus1 = secretToKeys(intToBytes(1));
    cipherkey_minus1, mackey_minus1 = secretToKeys(intToBytes(state["p"]-1));
    plain_plus1 = aes_cbc_dec(state["a_cipher"], cipherkey_plus1, state["a_iv"])
    plain_minus1 = aes_cbc_dec(state["a_cipher"], cipherkey_minus1, state["a_iv"])
    plain = None;
    try:
        plain = checkAndRemovePKCS7Padding(plain_plus1)
        state["m_key_a"] = cipherkey_plus1
    except ValueError:
        plain = checkAndRemovePKCS7Padding(plain_minus1)
        state["m_key_a"] = cipherkey_minus1
    state["m_plain_a"] = plain;
    # encrypt to B's key
    state["m_key_b"], b_mackey = secretToKeys(intToBytes(state["B"]))
    state["a_cipher"] = aes_cbc_enc(addPKCS7Padding(plain, 16), state["m_key_b"], state["a_iv"]);
    return state;
def message6_5_gp1(state):
    # decrypt message from B's key, encrypt to A's key
    state["m_plain_b"] = removePKCS7Padding(aes_cbc_dec(state["b_cipher"], state["m_key_b"], state["b_iv"]));
    state["b_cipher"] = aes_cbc_enc(addPKCS7Padding(state["m_plain_b"], 16), state["m_key_a"], state["b_iv"]);
    return state;
def check_protocol_gp1(state):
    # we've already computed the plaintexts...
    assert(state["m_plain_a"] == state["a_received_plain"]);
    assert(state["m_plain_b"] == state["b_received_plain"]);
def run_gp1():
    state = message1();
    state = message1_5_gp1(state);
    state = message2(state);
    state = message3(state);
    state = message3_5_gp1(state);
    state = message4(state);
    state = message5(state);
    state = message5_5_gp1(state);
    state = message6(state);
    state = message6_5_gp1(state);
    state = final(state);
    check_protocol(state);
    check_protocol_gp1(state);

    
    
if __name__ == "__main__":
    run_g1();
    run_gp();
    run_gp1();
    print("problem 35 success");