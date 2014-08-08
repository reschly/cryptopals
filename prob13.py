#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 13
from prob11 import generateAESKey
from prob10 import aes_ecb_enc
from prob7 import aes_ecb_dec
from prob9 import addPKCS7Padding

# 13. ECB cut-and-paste
# Write a k=v parsing routine, as if for a structured cookie. The
# routine should take
#   foo=bar&baz=qux&zap=zazzle
# and produce:
#
#  {
#    foo: 'bar',
#    baz: 'qux',
#    zap: 'zazzle'
#  }

def parseKeyValue(cookie):
    pairs = cookie.split("&");
    arrayResult = [p.split("=",1) for p in pairs];
    dictResult = {};
    for x in arrayResult:
        dictResult[x[0]] = x[1];
    return dictResult;

# Now write a function that encodes a user profile in that format, given
# an email address. You should have something like:
#  profile_for("foo@bar.com")
# and it should produce:
#  {
#    email: 'foo@bar.com',
#    uid: 10,
#    role: 'user'
#  }
# encoded as:
#  email=foo@bar.com&uid=10&role=user
# Your "profile_for" function should NOT allow encoding metacharacters
# (& and =). Eat them, quote them, whatever you want to do, but don't
# let people set their email address to "foo@bar.com&role=admin".

def profile_for(email):
    #remove =
    email = ''.join(email.split("="));
    #remove &
    email = ''.join(email.split("&"));
    result = "email=" + email + "&uid=10&role=user";
    return result;
    
# Now, two more easy functions. Generate a random AES key, then:
# (a) Encrypt the encoded user profile under the key; "provide" that
# to the "attacker".

aesKey = generateAESKey();
def encryptProfile(profile):
    return aes_ecb_enc(addPKCS7Padding(bytes(profile, 'UTF-8'), 16), aesKey);

def removePKCS7Padding(raw):
    num = raw[len(raw)-1];
    # should check padding values,
    # but need to carefully consider what to do on an error...
    return raw[0:(len(raw)-num)];

# (b) Decrypt the encoded user profile and parse it.
def decryptAndParseProfile(encProfile):
    decProfile = aes_ecb_dec(encProfile, aesKey);
    decProfile = removePKCS7Padding(decProfile);
    profile = parseKeyValue(decProfile.decode('UTF-8')); 
    return profile;


# Using only the user input to profile_for() (as an oracle to generate
# "valid" ciphertexts) and the ciphertexts themselves, make a role=admin
# profile.

def makeAdminProfile():
    # Observe: 
    # input "AAAA@BBBB.com" encrpts the blocks
    # email=AAAA@BBBB. com&uid=10&role= user\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c
    # input "XXXXXXXXXXadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@foo.com" encrypts as:
    # email=XXXXXXXXXX admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b @foo.com&uid...
    # Want cipher matching:
    # email=AAAA@BBBB. com&uid=10&role= admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b
    input1 = "AAAA@BBBB.com";
    input2 = "XXXXXXXXXXadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b@foo.com";
    cipher1 = encryptProfile(profile_for(input1));
    cipher2 = encryptProfile(profile_for(input2));
    adminCipher = cipher1[0:32] + cipher2[16:32];
    print("Admin Cipher: " + str(adminCipher));    
    print("Decrypted profile: " + str(decryptAndParseProfile(adminCipher)));
    pass;




if __name__ == "__main__":
    #test parseKeyValue;
    testCookie = "foo=bar&baz=qux&zap=zazzle"
    expectedParsedCookie= {"foo":"bar","baz":"qux","zap":"zazzle"};
    actualParsedCookie = parseKeyValue(testCookie);
    if (expectedParsedCookie != actualParsedCookie):
        print("Failed parseCookie test");
        print("Actual: " + str(actualParsedCookie));
        print("Expected: " + str(expectedParsedCookie));
    #test profile_for
    email = "fo=o@b&ar.&com"
    expectedProfile = "email=foo@bar.com&uid=10&role=user";
    actualProfile = profile_for(email);
    if (expectedProfile != actualProfile):
        print("Failed profile_for test");
        print("Actual:   " + str(actualProfile));
        print("Expected: " + str(expectedProfile));
    decryptedCookie = decryptAndParseProfile(encryptProfile(testCookie));
    if (decryptedCookie != actualParsedCookie):
        print("Failed decrypt/encrypt test");
        print("Actual:   " + str(decryptedCookie));
        print("Expected: " + str(actualParsedCookie));
    makeAdminProfile();
