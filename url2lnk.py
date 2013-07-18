#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import sys
import argparse

template = """[InternetShortcut]
URL=%s
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a lnk file with an URL')
    parser.add_argument('url', type=str)
    args = parser.parse_args()

    lnk = template % (args.url)
    sys.stdout.write(lnk)

