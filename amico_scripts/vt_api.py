###########################################################################
# Copyright (C) 2011-2013 Phani Vadrevu                                   #
# pvadrevu@uga.edu                                                        #
#                                                                         #
# Distributed under the GNU Public License                                #
# http://www.gnu.org/licenses/gpl.txt                                     #
#                                                                         #
# This program is free software; you can redistribute it and/or modify    #
# it under the terms of the GNU General Public License as published by    #
# the Free Software Foundation; either version 2 of the License, or       #
# (at your option) any later version.                                     #
#                                                                         #
###########################################################################
import urllib
import urllib2
import random

import postfile
import config
from config import *

TIMEOUT = 10


def get_vt_key():
    #random.seed()
    k = random.randint(0, len(vt_keys) - 1)
    print "Using VT API key number", k
    return vt_keys[k]  # vt_keys must be a list of valid virust_total API keys


def send_file(md5):
    host = "www.virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", get_vt_key())]
    if vt_submissions == "manual":
        file_to_send = open("%s/%s.exe" % (MAN_DOWNLOAD_DIR, md5), "rb").read()
    else:
        file_to_send = open("parsed/pe_files/%s.exe" % (md5,), "rb").read()

    files = [("file", "%s.exe" % (md5,), file_to_send)]
    json = postfile.post_multipart(host, selector, fields, files)
    return json


# Either a singe hash or a list of hashes (upto 25) can be passed
def rescan_request(arg):
    if isinstance(arg, list):
        res = ""
        for file_hash in arg:
            res += file_hash + ', '
        res = res[:-2]
    else:
        res = arg
    url = "https://www.virustotal.com/vtapi/v2/file/rescan"
    parameters = {"resource": res,
                  "apikey": get_vt_key()}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    try:
        response = urllib2.urlopen(req, timeout=5*TIMEOUT)
    except Exception as e:
        print "rescan_request: Exception occured", e
        return
    json = response.read()
    return json


# md5 or sha1 can also be used instead of scan_id
def get_vt_report(scan_id):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": scan_id,
                  "apikey": get_vt_key()}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    try:
        response = urllib2.urlopen(req, timeout=TIMEOUT)
    except Exception as e:
        print "get_vt_report: Exception occured", e
        return
    json = response.read()
    return json


def get_ip_report(ip):
    url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
    parameters = {"ip": ip,
                  "apikey": get_vt_key()}
    data = urllib.urlencode(parameters)
    req = urllib2.Request("%s?%s" % (url, data))
    try:
        response = urllib2.urlopen(req, timeout=TIMEOUT)
    except Exception as e:
        print "get_vt_report: Exception occured", e
        return
    json = response.read()
    return json
