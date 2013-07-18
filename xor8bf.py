#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xor8 between 1 - 255 and try to find the plain text.')
    parser.add_argument('plntxt', type=str,
                               help='the text to find after unxor')
    args = parser.parse_args()
    while True:
        data = sys.stdin.read(2048)
        if data == '':
            break
        r = xortools.single_byte_brute_xor(data, args.plntxt)
        if r[0] != None:
            print " [*] key is maybe 0x%02x" % r[0]


