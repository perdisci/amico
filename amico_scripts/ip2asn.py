##########################################################################
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

import sys
import psycopg2
import socks
import socket
import time
import subprocess

import util
from config import *


USER_AGENT = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
CYMRU_TIMEOUT = 1  # Timeout for cymru dig call


def ip2asn(dump_id):
    # Connect to database
    try:
        conn = psycopg2.connect("dbname=%s host=%s user=%s password=%s"
            % (db_name, db_host, db_user, db_password))
    except:
        print "Unable to connect to database: " + db_name

    # Use Autocommit mode for database connection
    conn.set_isolation_level(0)
    cursor = conn.cursor()

    # Setup SOCKS proxy
    if socks_proxy_host:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,
                        socks_proxy_host, socks_proxy_port)
        socket.socket = socks.socksocket
    ###

    # Database query to get the relevant recent record
    cursor.execute("""
        SELECT server, timestamp FROM pe_dumps WHERE dump_id = %s
            """, (dump_id,))
    row = cursor.fetchone()
    server_ip = row[0]
    # Exit if an AS containing this IP has been logged with in the last 1 month
    cursor.execute("""
        SELECT * FROM bgp2asn WHERE log_date > (current_date - interval '1 month')
        AND bgp_prefix >> %s """, (server_ip,))
    if cursor.rowcount > 0:
        return

    # Query whois.cymru.com
    #cmd = subprocess.Popen(['whois','-h','whois.cymru.com','-v',
    #       server_ip], stdout = subprocess.PIPE)
    #as_info = cmd.stdout
    #for line in as_info:
    #   if(server_ip in line):
    #       output = line.split('|')
    #       break
    #words=[]
    #for word in output:
    #   words.append(word.strip())

    # Query asn.cymru.com using dig
    # A sample output is:
    #     "701 1239 3549 3561 7132 | 216.90.108.0/24 | US | arin | 1998-09-25"
    print "making call"
    cmd = subprocess.Popen(['dig', '+short', util.reverse_ip(server_ip) +
                    '.origin.asn.cymru.com', 'TXT'], stdout=subprocess.PIPE)
    time.sleep(CYMRU_TIMEOUT)
    if cmd.poll() is None:
        cmd.kill()
        return
    as_info = cmd.stdout.readline()
    as_info = as_info.strip().strip('"')
    output = as_info.split('|')
    words = []
    for answer in output:
        if answer:
            words.append(answer.split()[0].strip())
        else:
            words.append(None)

    #print words
    as_number = words[0]
    bgp_prefix = words[1]
    country_code = words[2]
    date_allocated = words[4]

    # Sample output:
    #     "23028 | US | arin | 2002-01-04 | TEAMCYMRU - SAUNET"
    cmd = subprocess.Popen(['dig', '+short', 'AS' + as_number + '.asn.cymru.com',
                            'TXT'], stdout=subprocess.PIPE)
    time.sleep(CYMRU_TIMEOUT)
    if cmd.poll() is None:
        cmd.kill()
        print ("ip2asn.py: Couldn't finish the call to cymru for {0}. Aborting..."
                .format((server_ip,)))
        return
    as_info = cmd.stdout.readline()
    as_info = as_info.strip().strip('"')
    output = as_info.split('|')
    words = []
    for word in output:
        words.append(word.strip())
    print words
    as_name = words[4]

    # Store the record in the database
    cursor.execute("""
        INSERT INTO
            bgp2asn
            (bgp_prefix, as_number, as_name, country_code,
             date_allocated, log_date)
        VALUES (%s,%s,%s,%s,%s,current_date)"""
        , (bgp_prefix, as_number, as_name, country_code,
          date_allocated))

    cursor.close()
    conn.close()

if __name__ == "__main__":
    ip2asn(sys.argv[1])
