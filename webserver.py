#!/usr/bin/env python
# Written against python 3.3.1
# Simple web server to for problems 31/32
# Got tired of tryiing to install 
# non-python3 compatible web frameworks

import socketserver
import time
from prob31 import myhmac
from prob28 import sha1_from_github
from prob1 import hexToRaw

RESPONSE_500 = b'HTTP/1.1 500 Internal Server Error\n'
RESPONSE_200 = b'HTTP/1.1 200 OK\n'
COMPARE_DELAY = .050

HMAC_KEY = b'YELLOW SUBMARINE'

class MyWebServer(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            # typical url: http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
            line = self.rfile.readline().strip();
            if (line == None):
                break;
            file_index = line.find(b'file=')
            signature_index = line.find(b'&signature=')
            if ((file_index == -1 ) or (signature_index == -1)):
                continue;
            file_value = line[file_index + len(b'file='):signature_index]
            signature_hex = line[signature_index+len(b'&signature='):]
            computed_signature_hex = bytes(myhmac(sha1_from_github, file_value, HMAC_KEY), 'UTF-8');
            
            if (insecure_equals(hexToRaw(signature_hex), hexToRaw(computed_signature_hex))):
                self.wfile.write(RESPONSE_200);
            else:
                self.wfile.write(RESPONSE_500);
            

        self.wfile.write(self.data.upper())

def insecure_equals(this, that):
    if (len(this) != len(that)):
        return False;
    for i in range(len(this)):
        if (this[i] != that[i]):
            return False;
        time.sleep(COMPARE_DELAY);
    return True;

def start_server(delay):
    HOST, PORT = "localhost", 9000
    global COMPARE_DELAY
    COMPARE_DELAY=delay;
    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), MyWebServer)
    server.allow_reuse_address = True;

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()