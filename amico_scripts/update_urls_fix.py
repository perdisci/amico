# Author: Phani Vadrevu
#
# This script fixes a bug related to empty URLs in Amico's DB
# It reparses raw file dumps to fill missing URLs
# It should only be used to correct missing URLs produced
# by the version of Amico's code before "dev" branch commit
# b1d39fcf158441af61a59a571b342e9826a46c9d 

import logging
import re
import os

import util

RAW_FILE_DIR = "/home/perdisci/amico/amico_scripts/parsed/raw_files/"
LOG_FILE = "/home/perdisci/amico/amico_scripts/parsed/update_urls_amico.log"

def update_url(file_path,conn):
    #print "Time b4 http parsing: %f" %(time.time(),)
    # Use Autocommit mode for database connection

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
    # for efficiency purposes, skip files that were not affected by the bug
    url_line = fileHandle.readline()
    if " HTTP/1" in url_line:
        return

    r = re.compile('(GET|POST|HEAD) (.*)')
    url = r.search(url_line)
    if url is not None:
        method = url.group(1)
        method = method[:10]
        url = url.group(2)
        toks = url.split()
        url = toks[0]
        #print url.group(1)
    else:
        method = None

    if url is None or len(url.strip())==0:
        logging.warning('URL is empty for file: %s' % (file_path,))
        return


    cursor = conn.cursor()

    cursor.execute("""
        SELECT dump_id FROM pe_dumps
        WHERE timestamp = TO_TIMESTAMP(%s) AND server = %s AND client = %s
              AND dst_port = %s AND url IS NULL """, (timestamp, srcip, dstip, dst_port))
    if cursor.rowcount > 1:
        logging.warning('Found more than one dump_id for file: %s' % (file_path,))
    # elif cursor.rowcount == 0:
    #    logging.warning('Found no dump_id for file: %s', (file_path,))
    elif cursor.rowcount == 1:
        dump_id = cursor.fetchone()
        if len(url.strip())>0:
            cursor.execute("""
                UPDATE pe_dumps SET url = %s
                WHERE dump_id = %s """, (url.strip(), dump_id))
            logging.debug('Updated URL for dump_id: %s (file: %s | url: %s)' % (dump_id,file_path,url))


def main():
    conn = util.connect_to_db()

    logging.basicConfig(level=logging.DEBUG,
                        filename=LOG_FILE,
                        filemode='w')
    raw_file_names = os.listdir(RAW_FILE_DIR)
    for fn in raw_file_names:
        file_path = os.path.join(RAW_FILE_DIR, fn)
        print "Analyzing file:", file_path
        update_url(file_path,conn)


if __name__ == "__main__":
    main()
