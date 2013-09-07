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
import config
from config import *
import syslog
import re
import time

def reorder_domain(host):
    ordered_host = ""
    host += '.'
    domains = re.findall('.*?\.',host)
    for i in range(len(domains)):
        ordered_host += domains[len(domains)-i-1]
    ordered_host = ordered_host[:-1]
    return ordered_host


MIN_AV_LABELS = 1 


# Wait for db_virus_total to complete
WAIT_TIME = 60
time.sleep(WAIT_TIME)

# Connect to database
try:
    conn = psycopg2.connect("dbname=%s host=%s user=%s password=%s"
        %(db_name,db_host,db_user,db_password))
except:
    print "Unable to connect to database: "+db_name

# Use Autocommit mode for database connection
conn.set_isolation_level(0)
cursor = conn.cursor()

# Read Arguments
sha1 = sys.argv[1]
dump_id = sys.argv[2]

# Database query to get the relevant record  
cursor.execute("""
    SELECT timestamp,client,server,dst_port,host,url,referer,sha1,md5,file_size,
    MAX(trusted_av_labels) as av_labels,corrupt FROM pe_dumps JOIN
    virus_total_scans USING(sha1,md5) WHERE sha1 = '%s' 
    GROUP BY timestamp,client,server,dst_port,host,sha1,md5,url,referer,file_size,corrupt ORDER BY
    timestamp DESC LIMIT 1; """ % sha1)

# Make the syslog entry
log_data = cursor.fetchone()

cursor.execute("""
        SELECT score FROM amico_scores
        WHERE dump_id = %s """ , (dump_id, ))
score = None
if cursor.rowcount > 0:
    score = cursor.fetchone()[0]

if log_data:
    q = "PE file download -- timestamp: %s, client_ip: %s, server_ip: %s, server_port: %s, host: %s, url: %s, referrer: %s, sha1: %s, md5: %s, file_size: %s, av_labels: %s, corrupt: %s, amico_score: %s" % (log_data[0],log_data[1],log_data[2],log_data[3],reorder_domain(log_data[4]),log_data[5],log_data[6],log_data[7],log_data[8],log_data[9],log_data[10],log_data[11],score)
    #     syslog.syslog(syslog.LOG_ALERT,q)
    syslog.syslog(syslog.LOG_WARNING | syslog.LOG_USER, q)

cursor.close()
conn.close()
