#!/usr/bin/env python
# Name:
#    pe-carv.py
# Version:
#    0.3
#       * Added Ascii Blob and overlay functionality
# Description:
#    This script can be used to carve out portable executable files from a data stream.
#    It relies on pefile by Ero Carrera parse the portable executable format and calculate
#    the file size.
#
# Author
#    alexander<dot>hanel<at>gmail<dot>com
#
# License: Free game.. Please give credit

import re
import sys
from optparse import OptionParser
import imp

try:
    imp.find_module('pefile')
    import pefile
except ImportError as error:
    print '\t[IMPORT ERROR] %s - aborting' % error
    sys.exit()

class CARVER():
    def __init__(self):
        self.args = sys.argv
        self.buffer = ''
        self.outputF = ''
        self.parser = None
        self.asciiBlob = False
        self.location = 0
        self.help = None
        self.verbose = False
        self.overlay = False
        self.overlaySize = 512
        self.callParser()
        self.argumentCheck()
        self.readStream()
        self.convertAscii2Hex()
        self.carve()

    def argumentCheck(self):
        'check for arguments'
        if len(sys.argv) == 1:
            self.parser.print_help()
            sys.exit()

    def readStream(self):
        'read the file into a buffer'
        try:
            self.fileH = open(sys.argv[len(sys.argv)-1], 'rb')
            self.buffer = self.fileH.read()
        except:
            print '\t[FILE ERROR] could not access file: %s' % sys.argv[1]
            sys.exit()

    def getExt(self, pe):
        'returns ext of the file type using pefile'
        if pe.is_dll() == True:
            return 'dll'
        if pe.is_driver() == True:
            return 'sys'
        if pe.is_exe() == True:
            return 'exe'
        else:
            return 'bin'

    def writeFile(self, count, ext, pe):
        'write file to working directory'
        name = ''
        try:
            if self.outputF != '':
                out  = open( str(self.outputF) + '-' + str(count)+ '.' + ext, 'wb')
            else:
                out  = open(str(count) + '.' + ext, 'wb')
        except:
            print '\t[FILE ERROR] could not write file'
            sys.exit()
        # get size of trimmed file using PE
        trimmedPE = pe.trim()
        trimSize = len(trimmedPE)
        if self.overlay == True:
            tmpFileHandle = self.fileH
            tmpFileHandle.seek(self.location)
            try:
                trimmedPE = tmpFileHandle.read(trimSize+self.overlaySize)
            except:
                trimmedPE = tmpFileHandle.read()
        out.write(trimmedPE)
        out.close()

    def convertAscii2Hex(self):
        'converts the buffer from ascii to hex. all non-hex is whitespace'
        if self.asciiBlob == False:
            return
        from StringIO import StringIO
        tmp = StringIO(self.buffer)
        buff = ''
        b = tmp.read(2)
        while b != '':
            try:
                b = chr(int(b,16))
            except ValueError:
                b = ' '
            buff += b
            b = tmp.read(2)
        # replace the buffer with ascii to hex version.
        self.buffer = ''
        self.buffer = buff
        self.fileH = StringIO(buff)

    def callParser(self):
        'parse arguments for parser'
        self.parser = OptionParser()
        usage = 'usage: %prog [options] <carving.file>'
        self.parser = OptionParser(usage=usage)
        # command options
        self.parser.add_option('-o', '--output', type='string',dest='output', help='output file name')
        self.parser.add_option('-a', '--ascii_blob', action='store_true', dest='ascii', help='read as hex ascii blob')
        self.parser.add_option('-v', '--verbose', action='store_true', dest='verbose', help='print MZ location')
        self.parser.add_option('-l', '--overlay', action='store_true', dest='overlay', help='get overlay, default 1024 bytes')
        self.parser.add_option('-s', '--size', type='int', dest='size', help='size of overlay')
        (options, args) = self.parser.parse_args()
        if options.output != None:
            self.outputF = options.output
        if options.ascii == True:
            self.asciiBlob = True
        if options.verbose == True:
            self.verbose = True
        if options.overlay == True:
            self.overlay = True
        if options.size != None:
            self.overlaySize = options.size

    def carve(self):
        'carve out embeddded executables'
        c = 1
        # For each address that contains MZ
        for y in [tmp.start() for tmp in re.finditer('\x4d\x5a',self.buffer)]:
            self.location = y
            self.fileH.seek(y)
            try:
                pe = pefile.PE(data=self.fileH.read())
            except:
                print "Failed to parse EXE"
                continue
            # determine file ext
            ext = self.getExt(pe)
            if self.verbose == True:
                print '\t*', ext , 'found at offset', hex(y)
            self.writeFile(c,ext,pe)
            c += 1
            ext = ''
            self.fileH.seek(0)
            pe.close()

if __name__== '__main__':
    CARVER()

