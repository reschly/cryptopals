#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 30
# Break an MD4 keyed MAC using length extension.

# Second verse, same as the first, but use MD4 instead of SHA-1. Having
# done this attack once against SHA-1, the MD4 variant should take much
# less time; mostly just the time you'll spend Googling for an
# implementation of MD4.

# padding is the same for both
from prob1 import rawToHex
import struct

# From  https://github.com/josephw/python-md4 :

C = 0x1000000000

#--------------------------------------------------------------------
def norm(n):
    return n & 0xFFFFFFFF

#====================================================================
class U32:
    v = 0

    #--------------------------------------------------------------------
    def __init__(self, value = 0):
        self.v = C + norm(abs(int(value)))

    #--------------------------------------------------------------------
    def set(self, value = 0):
        self.v = C + norm(abs(int(value)))

    #--------------------------------------------------------------------
    def __repr__(self):
        return hex(norm(self.v))

    #--------------------------------------------------------------------
    def __long__(self): return int(norm(self.v))

    #--------------------------------------------------------------------
    def __int__(self): return int(norm(self.v))

    #--------------------------------------------------------------------
    def __index__(self): return int(self)

    #--------------------------------------------------------------------
    def __chr__(self): return chr(norm(self.v))

    #--------------------------------------------------------------------
    def __add__(self, b):
        r = U32()
        r.v = C + norm(self.v + b.v)
        return r

    #--------------------------------------------------------------------
    def __sub__(self, b):
        r = U32()
        if self.v < b.v:
            r.v = C + norm(0x100000000 - (b.v - self.v))
        else: r.v = C + norm(self.v - b.v)
        return r

    #--------------------------------------------------------------------
    def __mul__(self, b):
        r = U32()
        r.v = C + norm(self.v * b.v)
        return r

    #--------------------------------------------------------------------
    def __div__(self, b):
        r = U32()
        r.v = C + (norm(self.v) / norm(b.v))
        return r

    #--------------------------------------------------------------------
    def __mod__(self, b):
        r = U32()
        r.v = C + (norm(self.v) % norm(b.v))
        return r

    #--------------------------------------------------------------------
    def __neg__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __pos__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __abs__(self): return U32(self.v)

    #--------------------------------------------------------------------
    def __invert__(self):
        r = U32()
        r.v = C + norm(~self.v)
        return r

    #--------------------------------------------------------------------
    def __lshift__(self, b):
        r = U32()
        r.v = C + norm(self.v << b)
        return r

    #--------------------------------------------------------------------
    def __rshift__(self, b):
        r = U32()
        r.v = C + (norm(self.v) >> b)
        return r

    #--------------------------------------------------------------------
    def __and__(self, b):
        r = U32()
        r.v = C + norm(self.v & b.v)
        return r

    #--------------------------------------------------------------------
    def __or__(self, b):
        r = U32()
        r.v = C + norm(self.v | b.v)
        return r

    #--------------------------------------------------------------------
    def __xor__(self, b):
        r = U32()
        r.v = C + norm(self.v ^ b.v)
        return r

    #--------------------------------------------------------------------
    def __not__(self):
        return U32(not norm(self.v))

    #--------------------------------------------------------------------
    def truth(self):
        return norm(self.v)

    #--------------------------------------------------------------------
    def __cmp__(self, b):
        if norm(self.v) > norm(b.v): return 1
        elif norm(self.v) < norm(b.v): return -1
        else: return 0

    #--------------------------------------------------------------------
    def __bool__(self):
        return norm(self.v)


class MD4:
    A = None
    B = None
    C = None
    D = None
    count, len1, len2 = None, None, None
    buf = []

    #-----------------------------------------------------
    def __init__(self, A=0x67452301, B=0xefcdab89, C=0x98badcfe, D=0x10325476, numbytes=0):


        self.A = U32(A)
        self.B = U32(B)
        self.C = U32(C)
        self.D = U32(D)
        self.count, self.len1, self.len2 = U32(numbytes%64), U32((numbytes << 3) & 0xffffffff), U32((numbytes >> 29) & 0xffffffff)
        self.buf = [0x00] * 64

    #-----------------------------------------------------
    def __repr__(self):
        r = 'A = %s, \nB = %s, \nC = %s, \nD = %s.\n' % (self.A.__repr__(), self.B.__repr__(), self.C.__repr__(), self.D.__repr__())
        r = r + 'count = %s, \nlen1 = %s, \nlen2 = %s.\n' % (self.count.__repr__(), self.len1.__repr__(), self.len2.__repr__())
        for i in range(4):
            for j in range(16):
                r = r + '%4s ' % hex(self.buf[i+j])
            r = r + '\n'

        return r
    #-----------------------------------------------------
    def make_copy(self):

        dest = MD4()

        dest.len1 = self.len1
        dest.len2 = self.len2
        dest.A = self.A
        dest.B = self.B
        dest.C = self.C
        dest.D = self.D
        dest.count = self.count
        for i in range(self.count):
            dest.buf[i] = self.buf[i]

        return dest

    #-----------------------------------------------------
    def update(self, st):

        buf = []
        for i in st: buf.append(i)
        ilen = U32(len(buf))

        # check if the first length is out of range
        # as the length is measured in bits then multiplay it by 8
        if (int(self.len1 + (ilen << 3)) < int(self.len1)):
            self.len2 = self.len2 + U32(1)

        self.len1 = self.len1 + (ilen << 3)
        self.len2 = self.len2 + (ilen >> 29)

        L = U32(0)
        bufpos = 0
        while (int(ilen) > 0):
            if (64 - int(self.count)) < int(ilen): L = U32(64 - int(self.count))
            else: L = ilen
            for i in range(int(L)): self.buf[i + int(self.count)] = buf[i + bufpos]
            self.count = self.count + L
            ilen = ilen - L
            bufpos = bufpos + int(L)

            if (int(self.count) == 64):
                self.count = U32(0)
                X = []
                i = 0
                for j in range(16):
                    X.append(U32(self.buf[i]) + (U32(self.buf[i+1]) << 8)  + \
                    (U32(self.buf[i+2]) << 16) + (U32(self.buf[i+3]) << 24))
                    i = i + 4

                A = self.A
                B = self.B
                C = self.C
                D = self.D

                A = f1(A,B,C,D, 0, 3, X)
                D = f1(D,A,B,C, 1, 7, X)
                C = f1(C,D,A,B, 2,11, X)
                B = f1(B,C,D,A, 3,19, X)
                A = f1(A,B,C,D, 4, 3, X)
                D = f1(D,A,B,C, 5, 7, X)
                C = f1(C,D,A,B, 6,11, X)
                B = f1(B,C,D,A, 7,19, X)
                A = f1(A,B,C,D, 8, 3, X)
                D = f1(D,A,B,C, 9, 7, X)
                C = f1(C,D,A,B,10,11, X)
                B = f1(B,C,D,A,11,19, X)
                A = f1(A,B,C,D,12, 3, X)
                D = f1(D,A,B,C,13, 7, X)
                C = f1(C,D,A,B,14,11, X)
                B = f1(B,C,D,A,15,19, X)

                A = f2(A,B,C,D, 0, 3, X)
                D = f2(D,A,B,C, 4, 5, X)
                C = f2(C,D,A,B, 8, 9, X)
                B = f2(B,C,D,A,12,13, X)
                A = f2(A,B,C,D, 1, 3, X)
                D = f2(D,A,B,C, 5, 5, X)
                C = f2(C,D,A,B, 9, 9, X)
                B = f2(B,C,D,A,13,13, X)
                A = f2(A,B,C,D, 2, 3, X)
                D = f2(D,A,B,C, 6, 5, X)
                C = f2(C,D,A,B,10, 9, X)
                B = f2(B,C,D,A,14,13, X)
                A = f2(A,B,C,D, 3, 3, X)
                D = f2(D,A,B,C, 7, 5, X)
                C = f2(C,D,A,B,11, 9, X)
                B = f2(B,C,D,A,15,13, X)

                A = f3(A,B,C,D, 0, 3, X)
                D = f3(D,A,B,C, 8, 9, X)
                C = f3(C,D,A,B, 4,11, X)
                B = f3(B,C,D,A,12,15, X)
                A = f3(A,B,C,D, 2, 3, X)
                D = f3(D,A,B,C,10, 9, X)
                C = f3(C,D,A,B, 6,11, X)
                B = f3(B,C,D,A,14,15, X)
                A = f3(A,B,C,D, 1, 3, X)
                D = f3(D,A,B,C, 9, 9, X)
                C = f3(C,D,A,B, 5,11, X)
                B = f3(B,C,D,A,13,15, X)
                A = f3(A,B,C,D, 3, 3, X)
                D = f3(D,A,B,C,11, 9, X)
                C = f3(C,D,A,B, 7,11, X)
                B = f3(B,C,D,A,15,15, X)

                self.A = self.A + A
                self.B = self.B + B
                self.C = self.C + C
                self.D = self.D + D
                
        return self;

    #-----------------------------------------------------
    def digest(self):

        res = [0x00] * 16
        s = [0x00] * 8
        padding = [0x00] * 64
        padding[0] = 0x80
        padlen, oldlen1, oldlen2 = U32(0), U32(0), U32(0)

        temp = self.make_copy()

        oldlen1 = temp.len1
        oldlen2 = temp.len2
        if (56 <= int(self.count)): padlen = U32(56 - int(self.count) + 64)
        else: padlen = U32(56 - int(self.count))

        temp.update(int_array2str(padding[:int(padlen)]))

        s[0]= (oldlen1)        & U32(0xFF)
        s[1]=((oldlen1) >>  8) & U32(0xFF)
        s[2]=((oldlen1) >> 16) & U32(0xFF)
        s[3]=((oldlen1) >> 24) & U32(0xFF)
        s[4]= (oldlen2)        & U32(0xFF)
        s[5]=((oldlen2) >>  8) & U32(0xFF)
        s[6]=((oldlen2) >> 16) & U32(0xFF)
        s[7]=((oldlen2) >> 24) & U32(0xFF)
        temp.update(int_array2str(s))

        res[ 0]= temp.A        & U32(0xFF)
        res[ 1]=(temp.A >>  8) & U32(0xFF)
        res[ 2]=(temp.A >> 16) & U32(0xFF)
        res[ 3]=(temp.A >> 24) & U32(0xFF)
        res[ 4]= temp.B        & U32(0xFF)
        res[ 5]=(temp.B >>  8) & U32(0xFF)
        res[ 6]=(temp.B >> 16) & U32(0xFF)
        res[ 7]=(temp.B >> 24) & U32(0xFF)
        res[ 8]= temp.C        & U32(0xFF)
        res[ 9]=(temp.C >>  8) & U32(0xFF)
        res[10]=(temp.C >> 16) & U32(0xFF)
        res[11]=(temp.C >> 24) & U32(0xFF)
        res[12]= temp.D        & U32(0xFF)
        res[13]=(temp.D >>  8) & U32(0xFF)
        res[14]=(temp.D >> 16) & U32(0xFF)
        res[15]=(temp.D >> 24) & U32(0xFF)

        return int_array2str(res)

#====================================================================
# helpers
def F(x, y, z): return (((x) & (y)) | ((~x) & (z)))
def G(x, y, z): return (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
def H(x, y, z): return ((x) ^ (y) ^ (z))

def ROL(x, n): return (((x) << n) | ((x) >> (32-n)))

def f1(a, b, c, d, k, s, X): return ROL(a + F(b, c, d) + X[k], s)
def f2(a, b, c, d, k, s, X): return ROL(a + G(b, c, d) + X[k] + U32(0x5a827999), s)
def f3(a, b, c, d, k, s, X): return ROL(a + H(b, c, d) + X[k] + U32(0x6ed9eba1), s)

#--------------------------------------------------------------------
# helper function
def int_array2str(array):
        return bytes(array)
        st = b''
        for i in array:
            st = st + chr(i)
        return st

def generateMD4Padding(message_length_in_bytes):
    return b'\x80' + (b'\x00' * ((56 - (message_length_in_bytes + 1) % 64) % 64)) + struct.pack('<Q', message_length_in_bytes*8)


hash_secret = b'YELLOW SUBMARINE'

def dumbMD4HashAuth(key, message):
    return MD4().update(key + message).digest()

def checkDumbHashAuth(message, tag):
    return (dumbMD4HashAuth(hash_secret, message) == tag)

def appendMessage(original, tag, extra):    
    #assume secret is between 0 and 64 bytes in length
    for i in range(0, 65):
        oldpadding = generateMD4Padding(len(original)+i);
        newdata = extra;
        a = int.from_bytes(tag[0:4], byteorder='little');
        b = int.from_bytes(tag[4:8], byteorder='little');
        c = int.from_bytes(tag[8:12], byteorder='little');
        d = int.from_bytes(tag[12:16], byteorder='little');
        newtag = MD4(A=a, B=b, C=c, D=d, numbytes=i+len(original + oldpadding)).update(newdata).digest()
        if (checkDumbHashAuth(original + oldpadding + extra, newtag)):
            return newtag
    print("Failure");
    

def test30():
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    tag = dumbMD4HashAuth(hash_secret, message)
    newtag = appendMessage(message, tag, b';admin=true');
    print("new tag = ", rawToHex(newtag))
    print("Problem 30 success")

if (__name__ == "__main__"):
    test30();