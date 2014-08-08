#!/usr/bin/env python
# Written against python 3.3.1
# Matasano Problem 21
# Implement the MT19937 Mersenne Twister RNG
# generated from code on the wikipedia

class MT19937:
    def __init__(self, seed):
        self.MT = [0] * 624;
        self.index = 0;
        self.seed = 0;
        self.initialize_generator(seed);

    
#  function initialize_generator(int seed) {
#      i := 0
#      MT[0] := seed
#      for i from 1 to 623 { // loop over each other element
#          MT[i] := last 32 bits of(1812433253 * (MT[i-1] xor (right shift by 30 bits(MT[i-1]))) + i)
#      }
#  }
    def initialize_generator(self, seed):
        i = 0;
        self.MT[0] = seed;
        for i in range(1, 624):
            self.MT[i] = 0xffffffff & (0x6c078965 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i);
            
        
#  // Extract a tempered pseudorandom number based on the index-th value,
#  // calling generate_numbers() every 624 numbers
#  function extract_number() {
#      if index == 0 {
#          generate_numbers()
#      }
#  
#      int y := MT[index]
#      y := y xor (right shift by 11 bits(y))
#      y := y xor (left shift by 7 bits(y) and (2636928640)) // 0x9d2c5680
#      y := y xor (left shift by 15 bits(y) and (4022730752)) // 0xefc60000
#      y := y xor (right shift by 18 bits(y))
# 
#      index := (index + 1) mod 624
#      return y
#  }
    def extract_number(self):
        if (self.index == 0):
            self.generate_numbers();
            
        y = self.MT[self.index];        
        y = y ^ (y >> 11);
        y = y ^ ((y << 7) & 0x9d2c5680);
        y = y ^ ((y << 15) & 0xefc60000);
        y = y ^ (y >> 18);
        
        self.index = (self.index+1)%624
        return y;
            

#  // Generate an array of 624 untempered numbers
#  function generate_numbers() {
#      for i from 0 to 623 {
#          int y := (MT[i] & 0x80000000)                       // bit 31 (32nd bit) of MT[i]
#                         + (MT[(i+1) mod 624] & 0x7fffffff)   // bits 0-30 (first 31 bits) of MT[...]
#          MT[i] := MT[(i + 397) mod 624] xor (right shift by 1 bit(y))
#          if (y mod 2) != 0 { // y is odd
#              MT[i] := MT[i] xor (2567483615) // 0x9908b0df
#          }
#      }
#  }
    def generate_numbers(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1)%624] & 0x7fffffff);
            self.MT[i] = self.MT[(i+397)%624] ^ (y >> 1);
            if ((y%2) != 0):
                self.MT[i] = self.MT[i] ^ 0x9908b0df;


## The below is taken from http://my.opera.com/metrallik/blog/2013/04/19/python-class-for-random-generation-with-mersenne-twister 
## It is used to test the above, which I wrote

class operaRandom:
    """A Mersenne twister random generator"""
    length=624
    bitMask_32=(2**32)-1
    bitPow_31=2**31
    def __init__(self,seed):
        self.idx=0
        self.mt= [z for z in range(self.length)]
        self.mt[0]=seed
        for i in range(1,self.length):
            self.mt[i]=(1812433253*(self.mt[i-1]^(self.mt[i-1]>>30))+i)&self.bitMask_32

    def get(self):
        if self.idx==0:
            self.gen()
        y =self.mt[self.idx]
        y^= y>>11
        y^=(y<< 7)&2636928640
        y^=(y<<15)&4022730752
        y^= y>>18

        self.idx=(self.idx+1)%self.length
        return y

    def gen(self):
        for i in range(self.length):
            y=(self.mt[i]&self.bitPow_31)+(self.mt[(i+1)%self.length]&(self.bitPow_31-1))
            self.mt[i]=self.mt[(i+397)%self.length]^(y>>1)
            if y%2:
                self.mt[i]^=2567483615
        
if __name__ == "__main__":
    operaMT = operaRandom(12345);
    myMT = MT19937(12345);
    fail = False;
    for i in range(10000):
        op = operaMT.get();
        my = myMT.extract_number();
        if (op != my):
            print("fail: ", hex(op), hex(my));
            fail = True;
    if (not fail):
        print("prob21 success");

