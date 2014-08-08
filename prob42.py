#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 42
# Bleichenbacher's e=3 RSA Attack

from hashlib import sha1
from prob33 import mypow
from prob41 import generate_rsa_key

'''Side note: I was at the Crypto 2006 rump session where
Bleichenbacher presented this attack'''

sha1oid = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14' # from rfc 3447

def bad_rsa_sha1_verify(message, signature, rsaparams):
    decrypt = mypow(signature, rsaparams['e'], rsaparams['N']);
    decryptBytes = decrypt.to_bytes((rsaparams['N'].bit_length() + 7) // 8, byteorder="big");
    # check leading 0
    if (decryptBytes[0] != 0):
        return False;
    # block type 1
    if (decryptBytes[1] != 1):
        return False;
    # at least 1 0xff...
    if (decryptBytes[2] != 0xff):
        return False;
    # find end of ff's
    i = 3;
    while (i < len(decryptBytes)):
        if (decryptBytes[i]  != 0xff):
            break;
        i+=1
    # make sure there's enough room for 00, oid, hash
    if ((len(decryptBytes) - i) < (len(sha1oid) + 21)):
        return False;
    if (decryptBytes[i] != 0):
        return False;
    if (decryptBytes[i+1:i+1+len(sha1oid)] != sha1oid):
        return False;
    expectedHash = sha1(message).digest()
    if (decryptBytes[i+1+len(sha1oid):i+21+len(sha1oid)] != expectedHash):
        return False;
    return True;
    

# Forge a 1024-bit RSA signature for the string "hi mom"
def do_db_e3(message):
    hashvalue = bytes(sha1(message).digest());
    padding = b'\x00\x01\xff\xff\xff\xff\x00' #four bytes of 0xff
    shift = 128 - len(padding + sha1oid + hashvalue); # the '128' is due to RSA-1024
    basevalue = int.from_bytes(padding + sha1oid + hashvalue, byteorder="big") << (shift*8);
    sig = get_nth_root(basevalue, 3) + 1;
    return sig;

def get_nth_root(num, n):
    # returns the integer (x) such that
    # (x**n) <= num < ((x+1)**n)
    assert (num > 0);
    x = 1;
    # get an upper bound on x in log(num) time
    while (x**n < num):
        x = (x << 1);
    # back it up one
    x = (x >> 1);
    numbits = x.bit_length();
    # Find the precise number in log(num) time
    for bit in range(numbits-2, -1, -1):
        x = (x ^ (1 << bit));
        if (x**n > num):
            # if too large, mask it back out
            x = (x ^ (1 << bit));
    return x

def do_42():
    rsaparams = generate_rsa_key(1024, e=3);
    message = b'hi mom'
    signature = do_db_e3(message);
    assert(bad_rsa_sha1_verify(message, signature, rsaparams))
    
if __name__ == "__main__":
    do_42();
    print("problem 42 success");

    