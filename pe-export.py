#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import pefile
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='List exported function of a PE.')
    parser.add_argument('filename', metavar='filename', type=str,
                                               help='the DLL to use')
    args = parser.parse_args()
    filename = args.filename
    pe =  pefile.PE(filename)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
          print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),\
            exp.name, exp.ordinal

