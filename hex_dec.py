#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import config_path
import sys
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='decode hex format from stding.')
    args = parser.parse_args()
    data = sys.stdin.read()
    sys.stdout.write(data.replace('\n','').decode('hex'))
    #while True:
        #data = sys.stdin.read(2)
        #if data == '':
            #break
        #sys.stdout.write(data.decode('hex'))


