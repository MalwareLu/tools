#!/usr/bin/python
import httplib, mimetypes, simplejson, urllib, urllib2
import hashlib, time
import sys, getopt

apikey = ""

class bcolors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.GREEN = ''
        self.RED = ''
        self.ENDC = ''

# From VirusTotal API example https://www.virustotal.com/documentation/public-api/
# Upload file support
def post_multipart(host, selector, fields, files):
    """
    Post fields and files to an http host as multipart/form-data.
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return the server's response page.
    """
    content_type, body = encode_multipart_formdata(fields, files)
    h = httplib.HTTP(host)
    h.putrequest('POST', selector)
    h.putheader('content-type', content_type)
    h.putheader('content-length', str(len(body)))
    h.endheaders()
    h.send(body)
    errcode, errmsg, headers = h.getreply()
    return h.file.read()

def encode_multipart_formdata(fields, files):
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

# Return sha256 of a file
def filetohash(filename):
    file_content = open(filename, "rb").read()
    sha = hashlib.sha256(file_content).hexdigest()
    return sha

# Upload on VirusTotal
def upload(filename):
    host = "www.virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", apikey)]
    file_to_send = open(filename, "rb").read()
    files = [("file", filename, file_to_send)]
    json = post_multipart(host, selector, fields, files)
    result = simplejson.loads(json)
    return result

# Get report from a hash (md5, sha1, sha256, sha256+timestamp)
def report(resource):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": resource,
        "apikey": apikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    json = response.read()
    #print json
    result = simplejson.loads(json)
    return result

# Print a VirusTotal report
def format_report(result):
    scans = result.get("scans")
    for k, v in scans.items():
        if v['detected'] == True:
            print ("%s: %s%s%s") % (k, bcolors.RED, v['result'], bcolors.ENDC)
        else:
            print ("%s: %s-%s") % (k, bcolors.GREEN, bcolors.ENDC )

    print "-"*72
    print "SHA256: %s" % result['sha256']
    print "MD5: %s" % result['md5']
    print ("Detection ratio: %s%s/%s%s") % \
        (bcolors.RED, result['positives'], result['total'], bcolors.ENDC)
    print ("Analysis date: %s%s%s") % (bcolors.GREEN, result['scan_date'],  
        bcolors.ENDC)
    print "-"*72
    print "URL: %s" % result['permalink']

def usage():
    print "%s <file>" % sys.argv[0]
    print "%s --no-upload <file>" % sys.argv[0]
    print "%s -n <file>" % sys.argv[0]
    print "%s --hash <hash>" % sys.argv[0]
    print "%s -h <hash>" % sys.argv[0]
    print "%s --force <file>" % sys.argv[0]
    print "%s -f <file>" % sys.argv[0]
    print " -n don't upload the file if report not available"
    print " -h check if report exist for a hash"
    print " -f force a new scan for the file"

def main():
    if len(apikey) != 64:
        print "Please set your VirusTotal API key"
        sys.exit(2)

    try:
        opts, args = getopt.getopt(sys.argv[1:], 
            "fhn", ["force", "hash", "no-upload"])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        sys.exit(2)

    if len(args) == 0:
        usage()
        sys.exit(2)

    file_hash = None
    file_upload = True
    force = False
    check_hash = False
    for o, a in opts:
        if o in ("-n", "--no-upload"):
            file_upload = False
        elif o in ("-h", "--hash"):
            check_hash = True
        elif o in ("-f", "--force"):
            force = True
        else:
            assert False, "unhandled option"

    if check_hash == False:
        file_hash = filetohash(args[0])
    else:
        file_hash = args[0]
    
    if force == False: 
        r = report(file_hash)
        if r['response_code'] == 1:
            format_report(r)
            sys.exit(0)
        else:
            print "File %s not in VirusTotal or in queue" % file_hash
            if file_upload == False or check_hash == True:
                sys.exit(0)

    print "Upload in progress..."
    ru = upload(args[0])
    print ru['permalink']
    print ru['verbose_msg']

    print "Wait for report..." 
    r = report(ru['resource'])
    while r['response_code'] == 0:
        time.sleep(15)
        r = report(ru['resource'])
    
    format_report(r)

if __name__ == '__main__':
    main()

