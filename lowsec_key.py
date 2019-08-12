#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Florian Mortgat, 2019

Why is this low sec?
* use of sha256 as a pseudo-random number generator: this algorithm is not ideal
  for this.
* use of python’s random module for generating an initialization vector (IV)

'''
# TODO: truly stream (instead of reading 100% then printing out 100%)

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
    '''
    Convert an int to a bytes object of size BYTESIZE,
    endianness ENDIAN
    '''
    return int.to_bytes(n, BYTESIZE, ENDIAN)

def b2i(b):
    '''
    Convert a bytes object to an int using endianness
    ENDIAN
    '''
    return int.from_bytes(b, ENDIAN)

def pwd2key(pwd):
    '''
    Convert a unicode password into a bytes object that can
    be used as a key
    '''
    return pwd.encode('utf-8')

def rndstream(key, IV):
    '''
    Returns a generator for a pseudorandom stream determined
    by the key + initialization vector
    '''
    hash = sha256()
    while True:
        IV = (IV + 1) % MAX
        hash.update(i2b(IV))
        if key: hash.update(key)
        yield hash.digest()


def enc(key, txt):
    '''
    Encrypts txt using the provided key (a bytes object).
    '''
    ret = b''
    IV = random.randint(0, MAX-1)
    stream = rndstream(key, IV)
    while len(txt) >= BYTESIZE:
        block, txt = txt[0:BYTESIZE], txt[BYTESIZE:]
        encblock = i2b(b2i(block) ^ b2i(next(stream)))
        ret += encblock
    if len(txt):
        block = txt
        encblock = i2b(b2i(block) ^ b2i(next(stream)))[0:len(block)]
        ret += encblock
    return i2b(IV) + ret

def dec(key, txt):
    '''
    Decrypts txt (a text encrypted using enc).
    '''
    ret = b''
    IV, txt = b2i(txt[0:BYTESIZE]), txt[BYTESIZE:]
    stream = rndstream(key, IV)
    while len(txt) >= BYTESIZE:
        block, txt = txt[0:BYTESIZE], txt[BYTESIZE:]
        encblock = i2b(b2i(block) ^ b2i(next(stream)))
        ret += encblock
    if len(txt):
        block = txt
        encblock = i2b(b2i(block) ^ b2i(next(stream)))[0:len(block)]
        ret += encblock
    return ret

def stream_process(key,
        processor,
        f_in=sys.stdin.buffer,
        f_out=sys.stdout.buffer):
    '''
    Runs the input file/stream through processor and writes it to the output 
    file / stream.
    '''
    f_out.write(processor(key, f_in.read()))

stream_encrypt = partial(stream_process, enc)
stream_decrypt = partial(stream_process, dec)

def main():
    processors = {
            'enc': enc,
            'dec': dec
            }
    try:
        action = sys.argv[1]
        key = pwd2key(sys.argv[2])
        processor = processors[action]
        stream_process(key, processor)
    except IndexError:
        print('USAGE: cat FILE | lowsec1.py encode > ENCRYPTED_FILE')
        print('USAGE: cat ENCRYPTEDFILE | lowsec1.py decode > FILE')

if __name__ == '__main__': main()
