#!/usr/bin/python
# @Sebdraven

import teamcymru
import sys
import transformOnMD5
def usage():
	print '##### TeamCymru Submit #####'
	print 'ex: ./SubmitTeamCymru.py my_file'
	sys.exit()
if len(sys.argv) != 2:
	usage()

cmd='dig +short x.malware.hash.cymru.com TXT'
pathfile=sys.argv[1]
trsmd5=transformOnMD5.transformOnMD5(pathfile)
hashfile=trsmd5.calculMD5()
tc = teamcymru.teamcymru(hashfile,cmd)
print tc.submit()
