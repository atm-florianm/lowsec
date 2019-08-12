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
from typing import Generator, BinaryIO
from hashlib import sha256
from functools import partial

BITSIZE=256
BYTESIZE=BITSIZE>>3
MAX = 2**BITSIZE
ENDIAN = 'little'

def i2b(n: int) -> bytes:
    '''
    @param int n
    Convert an int to a bytes object of size BYTESIZE,
    endianness ENDIAN
    '''
    return int.to_bytes(n, BYTESIZE, ENDIAN)

def b2i(b: bytes) -> int:
    '''
    @param bytes b
    Convert a bytes object to an int using endianness
    ENDIAN
    '''
    return int.from_bytes(b, ENDIAN)

def pwd2key(pwd: str) -> bytes:
    '''
    @param string pwd
    @return bytes
    Convert a unicode password into a bytes object that can
    be used as a key. Currently it simply makes a bytes object
    from the unicode password.
    '''
    return pwd.encode('utf-8')

def rndstream(key: bytes, IV: int):
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

def xor_stream(stream_gen: Generator, txt: bytes):
    '''
    Generic function for encrypting and decrypting.
    It only XORs txt with the bits from stream_gen.
    '''
    ret = b''
    while len(txt) >= BYTESIZE:
        block, txt = txt[0:BYTESIZE], txt[BYTESIZE:]
        encblock = i2b(b2i(block) ^ b2i(next(stream_gen)))
        ret += encblock
    if len(txt):
        block = txt
        encblock = i2b(b2i(block) ^ b2i(next(stream_gen)))[0:len(block)]
        ret += encblock
    return ret
    

def stream_process(key: bytes,
        mode: str,
        f_in: BinaryIO=sys.stdin.buffer,
        f_out: BinaryIO=sys.stdout.buffer):
    '''
    Runs the input file/stream through processor and writes it to the output 
    file / stream.
    '''
    if mode == 'enc':
        IV = random.randint(0, MAX - 1)
        f_out.write(i2b(IV))
    elif mode == 'dec':
        IV = b2i(f_in.read(BYTESIZE))
    stream_gen = rndstream(key, IV)
    in_chunk = f_in.read(BYTESIZE)
    while len(in_chunk) == BYTESIZE:
        f_out.write(xor_stream(stream_gen, in_chunk))
        in_chunk = f_in.read(BYTESIZE)
    if (in_chunk):
        f_out.write(xor_stream(stream_gen, in_chunk))

stream_encrypt = partial(stream_process, 'enc')
stream_decrypt = partial(stream_process, 'dec')

def main():
    try:
        mode = sys.argv[1]
        key = pwd2key(sys.argv[2])
        stream_process(key, mode)
    except IndexError:
        print('USAGE: cat FILE | lowsec1.py encode > ENCRYPTED_FILE')
        print('USAGE: cat ENCRYPTEDFILE | lowsec1.py decode > FILE')

if __name__ == '__main__': main()
