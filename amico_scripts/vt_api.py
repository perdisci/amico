
# Author: Phani Vadrevu <pvadrevu@uga.edu>

import os.path
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

    dir_path = ""
    if vt_submissions == "manual":
        dir_path = MAN_DOWNLOAD_DIR
    else:
        dir_path = LIVE_DOWNLOAD_DIR 
    
    # just a patch to old code...
    # we only submit the first file that matches
    # it is anyway highly unlikely that more than one would match
    file_name = None
    file_path = None
    for ext in vt_submissions_ext:
        for e in [ext.lower(),ext.upper()]:
            fn = md5 + "." + e
            fp = os.path.join(dir_path,fn)
            if os.path.isfile(fp):
                file_name = fn
                file_path = fp
                break;

    if file_path and os.path.isfile(file_path):
        print "VT file submission:", file_path
        file_to_send = open(file_path, "rb").read()
        files = [("file", file_name, file_to_send)]
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
