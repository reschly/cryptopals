#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 8
# Implement PKCS#7 padding

def addPKCS7Padding(data, blocksize):
    numBytes = blocksize - (len(data) % blocksize);
    for i in range(numBytes):
        data += bytes(chr(numBytes), 'UTF-8');
    return data

def test9():
    input1 = b'abcd';
    expected1 = b'abcd\x04\x04\x04\x04'
    result1 = addPKCS7Padding(input1, 8);
    if (expected1 != result1):
        return False;
    input2 = b'I am a little teapot short and stout';
    expected2 = b'I am a little teapot short and stout\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c'
    result2 = addPKCS7Padding(input2, 16);
    if (expected2 != result2):
        return False;
    input3 = b'Yellow Submarine'
    expected3 = b'Yellow Submarine\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    result3 = addPKCS7Padding(input3, 16);
    if (expected3 != result3):
        return False;
    return True;


if __name__ == "__main__":
    if (test9()):
        print("Program 9 success");
    else:
        print("Failure");
        
    