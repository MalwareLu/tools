#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='xor the input in stdin with a key.')
    parser.add_argument('key', type=str,
                               help='the key')
    args = parser.parse_args()
    key = args.key
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        r = xortools.rolling_xor(data, key)
        sys.stdout.write(r)


