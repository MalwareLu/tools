#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xor8 the input in stdin.')
    parser.add_argument('key', metavar='key', type=str,
                               help='the key in hex or decimal format')
    args = parser.parse_args()
    key = int(args.key, 0) & 0xff
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        r = xortools.single_byte_xor(data, key)
        sys.stdout.write(r)


