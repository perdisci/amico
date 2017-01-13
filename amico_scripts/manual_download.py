###########################################################################
# Copyright (C) 2011 Phani Vadrevu, Roberto Perdisci                      #
# pvadrevu@uga.edu                                                        #
# perdisci@cs.uga.edu                                                     #
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

import sys
import re
import time
import hashlib
from struct import unpack
from config import capture_file_types
from extract_file import extract_file_type

import urllib2

import util
from config import MAN_DOWNLOAD_DIR

USER_AGENT = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
HTTP_TIMEOUT = 40  # HTTP Request timeout


# Take the request, download the file and generate sha1 and md5 hashes
# When the file is a valid pe and different from previous, then, save
# it to the downloads directory
def download_file(dump_id, req, captured_sha1):
    # Make the request
    try:
        res = urllib2.urlopen(req, timeout=HTTP_TIMEOUT).read()
    except urllib2.URLError, e:
        res = None
        print "Error making the manual download", e

    sha1 = None
    md5 = None
    is_interesting_file = None

    if res is None:
        print "Executable could not be downloaded manually"
    else:
        file_type = extract_file_type(res)
        if file_type in capture_file_types:
            print "Manually downloaded", file_type, "file"
            sha1 = hashlib.sha1(res).hexdigest()

            # Store the downloaded file in a sub directory as md5.exe
            md5 = hashlib.md5(res).hexdigest()

            download_file = open(MAN_DOWNLOAD_DIR + "/" + md5 + "." + file_type, "w")
            download_file.write(res)
            download_file.close()
            print "Written " + MAN_DOWNLOAD_DIR + "/" + md5 + "." + file_type
            is_interesting_file = True
        else:
            print "Manually downloaded an uninteresting file!"
            is_interesting_file = False

    if captured_sha1 != sha1:
        different = True
        print "Checksums did not match for dump_id: ", dump_id
        print captured_sha1, "!=", sha1
    else:
        different = False

    return sha1, md5, different, is_interesting_file


def manual_download(captured_sha1):
    util.setup_socks()
    conn = util.connect_to_db()
    cursor = conn.cursor()

    # Database query to get the relevant recent record
    cursor.execute("""
        SELECT dump_id,host,url,referer,client,server FROM pe_dumps WHERE sha1 = %s
            ORDER BY timestamp DESC;""", (captured_sha1,))
    row = cursor.fetchone()
    dump_id = row[0]
    host = row[1]
    url = row[2]
    referer = row[3]
    client = row[4]
    server = row[5]

    full_url = "http://"
    ordered_host = server # if host is null, we use ther server IP
    if host:
        ordered_host = util.reorder_domain(host)
    full_url += ordered_host
    if url:
        full_url += url
    print "Starting manual download from :", full_url

    # Prepare the urllib2 request
    req = urllib2.Request(full_url)
    req.add_header("User-Agent", USER_AGENT)

    download_time = time.time()
    sha1, md5, different, is_interesting_file = download_file(dump_id, req, captured_sha1)

    # Database statement
    cursor.execute("""
        INSERT INTO manual_download_checksums(dump_id, sha1,
        md5, different, referer_exists, timestamp, is_pe)
        VALUES (%s, %s, %s, %s, %s, TO_TIMESTAMP(%s), %s)""",
        (dump_id, sha1, md5, different, False, download_time, is_interesting_file))

    cursor.close()
    conn.close()

if __name__ == "__main__":
    manual_download(sys.argv[1])
