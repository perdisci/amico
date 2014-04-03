###########################################################################
# Copyright (C) 2011 Phani Vadrevu and Roberto Perdisci                   #
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
from datetime import datetime, timedelta, MINYEAR
import time

import simplejson
import logging
import logging.config

import util
import vt_api
from config import trusted_av_vendors

LOG_CONF_FILE = "logging.conf"


def insert_report():
    scan_time = report["scan_date"]
    scans = report["scans"]
    num_av_labels = report["positives"]
    trusted_av_labels = 0
    for k, v in scans.iteritems():
        if v["detected"] is True:
            if k in trusted_av_vendors:
                trusted_av_labels += 1
    scan_time += " UTC"
    cursor.execute("""
            INSERT INTO virus_total_scans(sha1,md5,json,num_av_labels,
            trusted_av_labels,scan_time,query_time)
            VALUES (%s,%s,%s,%s,%s,TIMESTAMP WITH TIME ZONE %s,CLOCK_TIMESTAMP()) 
            RETURNING vt_id
            """,(sha1,md5,json,num_av_labels,trusted_av_labels,scan_time))
    vt_id = cursor.fetchone()[0]

    cursor.execute("""
            INSERT INTO ped_vts_mapping (dump_id, vt_id)
            VALUES (%s, %s)""",
            (dump_id, vt_id))
    print "Virus Total: Scan report found. Entry has been made into"
    print "virus_total_scans table"

# Do not make a new query for the same sha1 if the previous query was made
# with in VT_QUERY_INTERVAL (in days)
VT_QUERY_INTERVAL = 1
MAX_TRIES = 5

logging.config.fileConfig(LOG_CONF_FILE)
logger = logging.getLogger("amico_logger")
util.setup_socks()
conn = util.connect_to_db()
cursor = conn.cursor()

dump_id = sys.argv[1]

# Exit if this sha1 has been queried in the past VT_QUERY_INTERVAL period
prev_query_time = datetime(MINYEAR, 1, 1, 0, 0, 0, 0)
time_now = datetime.now()
cursor.execute("""
    SELECT sha1, md5
    FROM pe_dumps
    WHERE dump_id = %s""",
    (dump_id,))
(sha1, md5) = cursor.fetchone()

try: 
    cursor.execute("SELECT query_time, vt_id FROM virus_total_scans "
               "WHERE sha1 = %s "
               "ORDER by query_time DESC",(sha1,))
    res = cursor.fetchone()
    if res:
        prev_query_time = res[0]
        vt_id = res[1]
except:
    print "sha1:%s no previous VT query"%(sha1, )
    pass

vt_query_period = timedelta(days=VT_QUERY_INTERVAL)
if (time_now - prev_query_time) < vt_query_period:
    print "sha1:%s has been queried recently. Skipping..."%(sha1, )
    cursor.execute("""
            INSERT INTO ped_vts_mapping (dump_id, vt_id)
            VALUES (%s, %s)""",
            (dump_id, vt_id))
    conn.close()
    sys.exit()

tries = 0
success = False
while tries < MAX_TRIES:
    try:
        tries += 1
        json = vt_api.get_vt_report(md5)
        if not json:
            continue
        report = simplejson.loads(json)
        if report["response_code"] == 1:
            insert_report()
            success = True
            break
        elif report["response_code"] == 0:
            cursor.execute("""
                INSERT INTO virus_total_scans(sha1, md5, query_time)
                VALUES (%s, %s, CLOCK_TIMESTAMP())
                RETURNING vt_id
                """, (sha1, md5))
            vt_id = cursor.fetchone()[0]
            cursor.execute("""
                    INSERT INTO ped_vts_mapping (dump_id, vt_id)
                    VALUES (%s, %s)""",
                    (dump_id, vt_id))
            print "Virus Total: No scan report exists in the VT database"
            success = True
            break
        else:
            logger.exception("Unknown response code! %s" %
                    (report["response_code"],))
            time.sleep(5)

    except Exception as e:
        print e
        logger.exception("Try %s. Error in fetching report for md5 %s: %s" % (tries, md5, e))
        time.sleep(5)
if not success:
    cursor.execute("""
            INSERT INTO ped_vts_mapping (dump_id)
            VALUES (%s)""",
            (dump_id,))
    logger.warning("Giving up on dump_id: %s's VT report" % (dump_id,))
cursor.close()
conn.close()
