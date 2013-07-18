#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='sub8 the input in stdin.')
    parser.add_argument('sub',  type=str,
                               help='the sub value in hex or decimal format')
    args = parser.parse_args()
    sub = int(args.sub, 0) & 0xff
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        for d in data:
            r = chr((ord(d) - sub) & 0xff)
            sys.stdout.write(r)


