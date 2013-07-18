#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='swap8 the input in stdin.')
    args = parser.parse_args()
    while True:
        data = sys.stdin.read(2)
        if data == '':
            break
        sys.stdout.write(data[::-1])


