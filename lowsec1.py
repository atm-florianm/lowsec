#!/usr/bin/env python3
'''
Florian Mortgat, 2019

Why is this low sec?
* use of sha256 as a pseudo-random number generator: this algorithm is not ideal
  for this.
* use of python’s random module for generating an initialization vector (IV)
* there is no key (the IV is the key)
'''
import os, sys
import re
import time
import random
from hashlib import sha256
from functools import partial

BITSIZE=256
BYTESIZE=BITSIZE>>3
MAX = 2**BITSIZE
ENDIAN = 'little'

def i2b(n):
    return int.to_bytes(n, BYTESIZE, ENDIAN)

def b2i(b):
    return int.from_bytes(b, ENDIAN)

def rndstream(iv):
    hash = sha256()
    while True:
        iv = (iv + 1) % MAX
        hash.update(i2b(iv))
        yield hash.digest()


def enc(txt):
    ret = b''
    IV = random.randint(0, MAX-1)
    stream = rndstream(IV)
    while len(txt) >= BYTESIZE:
        block, txt = txt[0:BYTESIZE], txt[BYTESIZE:]
        encblock = i2b(b2i(block) ^ b2i(next(stream)))
        ret += encblock
    if len(txt):
        block = txt
        encblock = i2b(b2i(block) ^ b2i(next(stream)))[0:len(block)]
        ret += encblock
    return i2b(IV) + ret

def dec(txt):
    ret = b''
    IV, txt = b2i(txt[0:BYTESIZE]), txt[BYTESIZE:]
    stream = rndstream(IV)
    while len(txt) >= BYTESIZE:
        block, txt = txt[0:BYTESIZE], txt[BYTESIZE:]
        encblock = i2b(b2i(block) ^ b2i(next(stream)))
        ret += encblock
    if len(txt):
        block = txt
        encblock = i2b(b2i(block) ^ b2i(next(stream)))[0:len(block)]
        ret += encblock
    return ret

def stream_process(processor, f_in=sys.stdin.buffer, f_out=sys.stdout.buffer):
        f_out.write(processor(f_in.read()))

stream_encrypt = partial(stream_process, enc)
stream_decrypt = partial(stream_process, dec)

def main():
    processors = {
            'enc': enc,
            'dec': dec
            }
    try:
        action = sys.argv[1]
        processor = processors[action]
        stream_process(processor)
    except IndexError:
        print('USAGE: cat FILE | lowsec1.py encode > ENCRYPTED_FILE')
        print('USAGE: cat ENCRYPTEDFILE | lowsec1.py decode > FILE')

if __name__ == '__main__': main()
