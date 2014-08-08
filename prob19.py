#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 19
# Break fixed-nonce CTR inefficiently... 
from prob1 import base64toRaw
from prob18 import raw_xor, aes_ctr
from prob11 import generateAESKey
from prob17 import setByte

# You know, I'd really rather do this the problem-20 way...

b64plain = [ b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==', \
b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=', \
b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==', \
b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=', \
b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk', \
b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', \
b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=', \
b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', \
b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=', \
b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl', \
b'VG8gcGxlYXNlIGEgY29tcGFuaW9u', \
b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==', \
b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=', \
b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==', \
b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=', \
b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=', \
b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==', \
b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==', \
b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==', \
b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==', \
b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==', \
b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==', \
b'U2hlIHJvZGUgdG8gaGFycmllcnM/', \
b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=', \
b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=', \
b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=', \
b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=', \
b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==', \
b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==', \
b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=', \
b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==', \
b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu', \
b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=', \
b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs', \
b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=', \
b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0', \
b'SW4gdGhlIGNhc3VhbCBjb21lZHk7', \
b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=', \
b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=', \
b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=', \
];

rawPlain = [base64toRaw(b) for b in b64plain];
longestPlaintextLength = max([len(p) for p in rawPlain]);

aeskey = generateAESKey();

rawCiphers = [aes_ctr(p, aeskey, b'\x00' * 16) for p in rawPlain]; 

def printSolution(guess, ciphers):
    print("------------------------------");
    print("Guess: ", guess);
    for i in range(len(ciphers)):
        print("Plain ", i, ": " , raw_xor(ciphers[i], guess));
        
def solve19():
    # initial guess: Assume every plaintext char is a space.  Guess the key that creates the most spaces
    guess = b'';
    for i in range(longestPlaintextLength):
        myDict = {};
        for j in range(256):
            myDict[chr(j)] = 0;
        for p in rawCiphers:
            try:
                myDict[chr(p[i] ^ 0x20)] += 1;
            except Exception: # out of range...
                pass;
        guess += ord(max(myDict, key=lambda k: myDict[k])).to_bytes(1, byteorder='big');
    printSolution(guess, rawCiphers);
    # Notice that the first plain says "(ehav*o)".  Guess that this should be "Behavior".    
    guess = setByte(guess, 0, rawCiphers[0][0] ^ ord('B'));
    guess = setByte(guess, 1, rawCiphers[0][1] ^ ord('e'));
    guess = setByte(guess, 5, rawCiphers[0][5] ^ ord('i'));
    guess = setByte(guess, 7, rawCiphers[0][7] ^ ord('r'));
    printSolution(guess, rawCiphers);
    # Notice that the last plain starts with "Jeter~&}l- bea0ty" -- guess this should be "beauty"
    guess = setByte(guess, 13, rawCiphers[39][13] ^ ord('a'));
    guess = setByte(guess, 14, rawCiphers[39][14] ^ ord('u'));
    printSolution(guess, rawCiphers);
    # Plain (21) has "beau1i#ul" -- guess this should be beautiful
    guess = setByte(guess, 19, rawCiphers[21][19] ^ ord('t'));
    guess = setByte(guess, 21, rawCiphers[21][21] ^ ord('f'));
    guess = setByte(guess, 23, rawCiphers[21][23] ^ ord('l'));
    printSolution(guess, rawCiphers);
    # Plain  24 :  b"J+d rc+z 'ur winged hors6." -- probably supposed to end in horse.
    guess = setByte(guess, 24, rawCiphers[24][24] ^ ord('e'));
    printSolution(guess, rawCiphers);
    # Plain  7 :  b'[*litiore)ningless words,' -- should be " meaningless"?
    guess = setByte(guess, 9, rawCiphers[7][9] ^ ord('a'));
    guess = setByte(guess, 7, rawCiphers[7][7] ^ ord('m'));
    guess = setByte(guess, 6, rawCiphers[7][6] ^ 0x20);
    printSolution(guess, rawCiphers);
    # Plain  3 :  b'N,ghtienth-century houses.' -- should start 'Eighteenth'?
    guess = setByte(guess, 0, rawCiphers[3][0] ^ ord('E'));
    guess = setByte(guess, 1, rawCiphers[3][1] ^ ord('i'));
    guess = setByte(guess, 5, rawCiphers[3][5] ^ ord('e'));
    printSolution(guess, rawCiphers);
    # a Google for "from counter or desk" took me to http://www.poetryfoundation.org/poem/172061 to fill in the rest:
    # (heh -- just noticed that my first guess ("Behavior") was completely wrong...)
    # Plain  37 :  b'He, too, has been changed &ne 07 x46  ' shoudl be: He, too, has been changed in his turn,  
    guess = setByte(guess, 8, rawCiphers[37][8] ^ ord(' '));
    guess = setByte(guess, 26, rawCiphers[37][26] ^ ord('i'));
    guess = setByte(guess, 28, rawCiphers[37][28] ^ ord(' '));
    guess = setByte(guess, 29, rawCiphers[37][29] ^ ord('h'));
    guess = setByte(guess, 30, rawCiphers[37][30] ^ ord('i'));
    guess = setByte(guess, 31, rawCiphers[37][31] ^ ord('s'));
    guess = setByte(guess, 32, rawCiphers[37][32] ^ ord(' '));
    guess = setByte(guess, 33, rawCiphers[37][33] ^ ord('t'));
    guess = setByte(guess, 34, rawCiphers[37][34] ^ ord('u'));
    guess = setByte(guess, 35, rawCiphers[37][35] ^ ord('r'));
    guess = setByte(guess, 36, rawCiphers[37][36] ^ ord('n'));
    guess = setByte(guess, 37, rawCiphers[37][37] ^ ord(','));
    printSolution(guess, rawCiphers);
    
if __name__ == "__main__":
    solve19();