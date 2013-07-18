#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse
import xortools

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='add8 the input in stdin.')
    parser.add_argument('add',  type=str,
                               help='the sub value in hex or decimal format')
    args = parser.parse_args()
    add = int(args.add, 0) & 0xff
    while True:
        data = sys.stdin.read(4)
        if data == '':
            break
        for d in data:
            r = chr((ord(d) + add) & 0xff)
            sys.stdout.write(r)


