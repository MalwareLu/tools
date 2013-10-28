import os
import simplejson

class teamcymru(object):
	
	def __init__(self,md5,cmd):
		self.md5=md5
		self.cmd=cmd


	def submit(self):
		self.cmd = self.cmd.replace('x',self.md5)
		print 'Submit '+ self.cmd
		result=os.popen(self.cmd)
		
		result=result.readlines()
		if len(result)> 0:		
			result=result[0]
			result=result.replace('\n','')
			result=result.replace('"','')
			if result != '127.0.0.2':
				timestamp=result.split(' ')[0]
				malwarepercent=result.split(' ')[1]
				data = simplejson.dumps({'timestamp':timestamp,'malwarepercent':malwarepercent},sort_keys=True)
				print data
				return data	
