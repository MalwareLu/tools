#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
#import config_path
import sys
import argparse
from Crypto.Cipher import ARC4

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='RC4 the input in stdin.')
    parser.add_argument('key', type=str)
    args = parser.parse_args()
    rc4 = ARC4.new(args.key)
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        r = rc4.encrypt(data)
        sys.stdout.write(r)


