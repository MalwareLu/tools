#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Malware.lu
import sys
import argparse
import requests
from termcolor import colored
from lxml import html
import jsbeautifier
import dns.resolver # dnspython
from urlparse import urlparse
import pygeoip
import urllib2, urllib

geoip_db = "/usr/share/GeoIP/GeoIP.dat" # from package ubuntu geoip-database

def check_blacklist_dns(ip):
    provider = ['dnsbl.sorbs.net', 'cbl.abuseat.org',
            'bl.spamcop.net', 'zen.spamhaus.org',
            'sbl.spamhaus.org', 'xbl.spamhaus.org',
            'pbl.spamhaus.org', 'combined.abuse.ch',
            'dbl.spamhaus.org',
            'drone.abuse.ch', 'spam.abuse.ch',
            'dnsbl.abuse.ch',
            'httpbl.abuse.ch', 'ipbl.zeustracker.abuse.ch',
            'uribl.zeustracker.abuse.ch',
            'psbl.surriel.com', 'bl.blocklist.de',
            'bsb.empty.us', 'b.barracudacentral.org',
            'bb.barracudacentral.org', 'bl.dronebl.org',
            'origin.asn.cymru.com', 'peer.asn.cymru.com']
    ip_rev = '.'.join(reversed(ip.split('.')))

    for blacklist in provider:
        check_domain = "%s.%s" % (ip_rev, blacklist)
        try:
            answers = dns.resolver.query(check_domain)
            ip = answers[0].to_text()
            print colored("%s: %s" % (blacklist, ip), "red")
        except Exception, e:
            pass


def google_safebrowsing(url):
    api_key = "ABQIAAAA55hJZAWo2KBLCGcGYtI03BSLNEcy237KLTt66fvN757NqGaakA"
    app = "blackchecker"
    url_api = "https://sb-ssl.google.com/safebrowsing/api/lookup" + \
        "?client=%s&apikey=%s&appver=1.5.2&pver=3.0&url=%s"

    url_api = url_api % (app, api_key, urllib.quote(url, ''))
    #print url_api

    # failed with requests modules proxy return 501 weird :s
    # req = requests.get(url_api)
    req = urllib2.urlopen(url_api)
    result = req.read()
    print "%d:%s" % (req.code, result )

def cybercrime_tracker(domain):
    #curl http://cybercrime-tracker.net/all.php | sed 's/<[^>]*>/\n/g' > /work/db/cybercrime-tracker.txt
    cc_tracker_file = "/work/db/cybercrime-tracker.txt"
    fp = open(cc_tracker_file)
    domain = domain.lower()
    for line in fp:
        line = line.strip('\n').lower()
        if domain in line:
            print colored("%s" % line, "red")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract usefull information from html page')
    parser.add_argument('url', type=str)
    args = parser.parse_args()


    up = urlparse(args.url)
    domain = up.netloc
    print colored("Domain lookup: %s" % domain, "green")
    answers = dns.resolver.query(domain )
    print "TTL: %d" % answers.rrset.ttl
    geoip = pygeoip.GeoIP(geoip_db)

    ips = []
    for rdata in answers:
        if rdata.to_text() != domain:
            ips.append(rdata.to_text())
        cc = geoip.country_code_by_name(rdata.to_text())
        print "%s %s" % (rdata.to_text(), cc)

    print ""
    print colored("Blacklist check: %s" % domain, "green")
    check_blacklist_dns(domain)
    for ip in ips:
        print colored("Blacklist check: %s" % ip, "green")
        check_blacklist_dns(ip)

    print ""
    print colored("Google safebrowsing: %s" % args.url, "green")
    google_safebrowsing(args.url)

    print ""
    print colored("Cybercrime tracker: %s" % domain, "green")
    cybercrime_tracker(domain)

    print ""
    req = requests.get(args.url)
    print colored("Server header:", "green")
    print "%s" % (req.status_code)
    for k,v in req.headers.items(): print "%s: %s" % (k, v)

    print ""
    tree = html.fromstring(req.content)
    info = tree.xpath('//a')
    print colored("Links found (%d):" % len(info), "green")
    for h in info:
        print "uri: %s" % \
              (h.attrib.get('href', ''))
        #print "title: %s uri: %s" % \
              #(h.attrib.get('title', ''),
              #h.attrib.get('href', ''))

    print ""
    info = tree.xpath('//script')
    print colored("Javascript found (%d):" % len(info), "green")
    for h in info:
        print "-"*32
        print "src: %s" %  h.attrib.get('src', '')
        if h.text:
            print "content:"
            opts = jsbeautifier.default_options()
            opts.unescape_strings = True
            opts.eval_code = True # dangerous
            print jsbeautifier.beautify(h.text)

    print ""
    info = tree.xpath('//iframe')
    print colored("Iframe found (%d):" % len(info), "green")
    for h in info:
        print "-"*32
        print "src=\"%s\" width=%s height=%s" % \
                (h.attrib.get('src', ''),
                 h.attrib.get('width', ''),
                 h.attrib.get('height', ''))


    print ""
    info = tree.xpath('//applet')
    print colored("Java found (%d):" % len(info), "green")
    for h in info:
        print "-"*32
        print "object=\"%s\" code=\"%s\" width=%s height=%s" % \
                (h.attrib.get('code', ''),
                 h.attrib.get('object', ''),
                 h.attrib.get('width', ''),
                 h.attrib.get('height', ''))

    print ""
    info = tree.xpath('//object')
    print colored("Object found (%d):" % len(info), "green")
    for h in info:
        print "-"*32
        print "data=\"%s\" classid=\"%s\" codebase=\"%s\" width=%s height=%s" % \
                (h.attrib.get('data', ''),
                 h.attrib.get('classid', ''),
                 h.attrib.get('codebase', ''),
                 h.attrib.get('width', ''),
                 h.attrib.get('height', ''))

        subinfo = h.xpath('param')
        for sh in subinfo:
           print "name=%s value=%s" % \
                (sh.attrib.get('name', ''),
                 sh.attrib.get('value', ''))

        subinfo = h.xpath('embed')
        for sh in subinfo:
           print "src=\"%s\" width=%s height=%s" % \
               (sh.attrib.get('src', ''),
                sh.attrib.get('width', ''),
                sh.attrib.get('height', ''))


