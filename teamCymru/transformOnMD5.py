import os
import glob
import sys
import hashlib
import os

class transformOnMD5(object):
	
	def __init__(self,pathfile):
		self.pathfile=pathfile
	
	def calculMD5(self):
		if self.pathfile !='':
			f=open(self.pathfile,'r')
			m = hashlib.md5()
			m.update(f.read())
			return m.hexdigest()
		else:
			print 'Missing File ' + self.pathfile
	
	def copy(self,src,dst):
		
		if os.path.isfile(src) and os.path.isfile(dst)== False:		
				os.rename(src, dst)
		elif os.path.isfile(src)==False:
			print "File does'nt exist "+ src
		elif os.path.isfile(dst)==True:
			os.remove(src)
			print 'File already exists ' +dst
		return dst
