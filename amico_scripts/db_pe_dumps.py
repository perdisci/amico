###########################################################################
# Copyright (C) 2011 Phani Vadrevu                                        #
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

import re
import sys
from config import *

import util

def db_pe_dumps(file_path, sha1, md5, file_size):
    #print "Time b4 http parsing: %f" %(time.time(),)
    # Use Autocommit mode for database connection
    conn = util.connect_to_db()
    cursor = conn.cursor()

    fileHandle = open(file_path)

    # Timestamp
    r = re.compile('[0-9]+')
    timestamp = r.search(fileHandle.readline())
    if timestamp is not None:
        timestamp = timestamp.group()
        #print timestamp.group()

    # Source and Destination IPs
    r = re.compile('([0-9.]+):.*-([0-9.]+):([0-9]+)-.*')
    ip = r.search(fileHandle.readline())
    if ip is not None:
        srcip = ip.group(2)
        dstip = ip.group(1)
        dst_port = ip.group(3)
        #print ip.group(1)
        #print ip.group(2)
    else:
        srcip = None
        dstip = None
        dst_port = None

    # URL
    r = re.compile('(GET|POST|HEAD) (.*) ')
    url = r.search(fileHandle.readline())
    if url is not None:
        method = url.group(1)
        method = method[:10]
        url = url.group(2)
        #print url.group(1)
    else:
        method = None


    # Host
    r = re.compile('Host: (.*)')
    host = r.search(fileHandle.readline())
    if host is not None:
        host = host.group(1)
        host = util.reorder_domain(host.strip())
        #print host.group(1)


    # Referer
    r = re.compile('Referer: (.*)')
    referer = r.search(fileHandle.readline())
    if referer is not None:
        referer = referer.group(1)
        #print referrer.group(1)


    # CORRUPT_PE
    corrupt_pe = "FALSE"
    r = re.compile('CORRUPT_PE')
    corrupt_pe_str = r.search(fileHandle.readline())
    if corrupt_pe_str is not None:
        corrupt_pe = "TRUE"


    # Now, parse data from the response
    # Server
    data = fileHandle.read()
    r = re.compile('Server: (.*)')
    server = r.search(data)
    if server is not None:
        server = server.group(1)
        server = server.rstrip('\r')
        server = server[:64]

    # Content-Type
    r = re.compile('Content-Type: (.*)')
    cont_type = r.search(data)
    if cont_type is not None:
        cont_type = cont_type.group(1)
        cont_type = cont_type.rstrip('\r')
        cont_type = cont_type[:128]

    #print "Time after http parsing: %f" %(time.time(),)
    # Database statement
    cursor.execute("""
        INSERT INTO pe_dumps(sha1,md5,timestamp,server,client,method,url,host,
        referer,server_application,content_type,dst_port,corrupt,file_size)
        VALUES
        (%s,%s,TO_TIMESTAMP(%s),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (sha1, md5, timestamp, srcip, dstip, method, url, host, referer, server,
        cont_type, dst_port, corrupt_pe, file_size))
    cursor.execute("""
        SELECT dump_id FROM pe_dumps where sha1 = %s ORDER BY dump_id DESC
        """, (sha1,))
    dump_id = cursor.fetchone()[0]
    print ("A new entry on host:%s has been made in pe_dumps table with "
          "dump_id %s" % (host, dump_id))

    fileHandle.close()
    cursor.close()
    conn.close()
    return dump_id, corrupt_pe


if __name__ == "__main__":
    file_path = sys.argv[1]
    sha1 = sys.argv[2]
    md5 = sys.argv[3]
    file_size = sys.argv[4]
    db_pe_dumps(file_path, sha1, md5, file_size)
