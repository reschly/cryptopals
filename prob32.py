#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 32
# Break HMAC-SHA1 with a slightly less artificial timing leak.
from prob1 import rawToHex
import threading
import webserver
import time
import socket
import os
from prob17 import setByte

# .005: Would get the first four right
# .001: Got the first one wrong
# My response: raise iteration count to 10 -- would still get first one wrong
# raise to 20: would get first one wrong
# raise to 50: Seems to be working again
DELAY = .001
    
def startserver(delay):
    server_thread = threading.Thread(target=webserver.start_server, args=[delay])
    server_thread.start();   

# Using the timing leak in this application, write a program that
# discovers the valid MAC for any file.                
def discover_mac(message):
    guess_mac = b'\x00' * 20;
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    sock.connect(('127.0.0.1', 9000))
    for i in range(20):
        nextbyte = guess_byte(sock, message, i, guess_mac);
        guess_mac = setByte(guess_mac, i, nextbyte);
    print (rawToHex(guess_mac));
    return guess_mac;


def guess_byte(sock, message, index, guess_mac, numtrials=50):
    timings = [0]*256;
    # try each byte at the index
    for i in range(256):
        this_guess = setByte(guess_mac, index, i);
        url = b'test?file=' + message + b'&signature=' + rawToHex(this_guess) + b'\n';
        start = time.perf_counter()
        for j in range(numtrials):
            sock.send(url);        
            data = sock.recv(1024)
        stop = time.perf_counter()
        timings[i] = stop - start;
    # assume the largest timing is the right one
    value = timings.index(max(timings));
    print("index: " + str(index) + " : value: " + hex(value));
    return value;

        


def do32():
    startserver(DELAY);
    #known answer: b'6262261f054f0a17dfa68d87bf64f5416c128340'
    discover_mac(b'Mary had a little lamb');


if __name__ == "__main__":
    do32();
    os._exit(0);