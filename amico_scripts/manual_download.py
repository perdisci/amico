
# Author: Phani Vadrevu <pvadrevu@uga.edu>

import sys
import re
import time
import hashlib
from struct import unpack

import urllib2

import util
from config import MAN_DOWNLOAD_DIR

USER_AGENT = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
HTTP_TIMEOUT = 40  # HTTP Request timeout

# checks for valid PE header
def is_pe_file(bin_data):
    if not bin_data:
        return False

    if len(bin_data) <= 0:
        return False

    m = re.search('MZ', bin_data)
    if m:
        p = m.start()
        offset = p + unpack('i', bin_data[p+0x3c:p+0x3c+4])[0]
        # print "p=", p, "  offset=", offset
        if bin_data[p:p+2] == 'MZ' and bin_data[offset:offset+2] == 'PE':
            # print "This is a PE file!"
            return True

    print "This is NOT a PE file!"
    return False


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
    is_pe = None

    if res is None:
        print "Executable could not be downloaded manually"
    else:
        if is_pe_file(res):
            sha1 = hashlib.sha1(res).hexdigest()

            # Store the downloaded file in a sub directory as md5.exe
            md5 = hashlib.md5(res).hexdigest()

            download_file = open(MAN_DOWNLOAD_DIR + "/" + md5 + ".exe", "w")
            download_file.write(res)
            download_file.close()
            print "Written " + MAN_DOWNLOAD_DIR + "/" + md5 + ".exe"
            is_pe = True
        else:
            print "Downloaded a non-PE file!"
            is_pe = False
    if captured_sha1 != sha1:
        different = True
        print "Checksums did not match for dump_id: ", dump_id
    else:
        different = False
    return sha1, md5, different, is_pe


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

    if host is None:
        host = server
    ordered_host = util.reorder_domain(host)
    full_url = "http://" + ordered_host + url
    #print full_url

    # Prepare the urllib2 request
    req = urllib2.Request(full_url)
    req.add_header("User-Agent", USER_AGENT)

    download_time = time.time()
    sha1, md5, different, is_pe = download_file(dump_id, req, captured_sha1)

    # Database statement
    cursor.execute("""
        INSERT INTO manual_download_checksums(dump_id, sha1,
        md5, different, referer_exists, timestamp, is_pe)
        VALUES (%s, %s, %s, %s, %s, TO_TIMESTAMP(%s), %s)""",
        (dump_id, sha1, md5, different, False, download_time, is_pe))

    cursor.close()
    conn.close()

if __name__ == "__main__":
    manual_download(sys.argv[1])
