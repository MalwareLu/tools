#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xor32 the input in stdin.')
    parser.add_argument('key', type=str,
                               help='the key in hex or decimal format')
    args = parser.parse_args()
    key = int(args.key, 0) & 0xffffffff
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        r = xortools.four_byte_xor(data, key)
        sys.stdout.write(r)


