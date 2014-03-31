##########################################################################
# copyright (c) 2011 phani vadrevu                                        #
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
from config import amico_threshold
import syslog
import time

import util
from util import reorder_domain


def make_syslog_entry(cursor, dump_id):
    # Database query to get the relevant record
    cursor.execute("""
        SELECT timestamp, client, server, dst_port, host, url, referer,
            pe.sha1, pe.md5, file_size, trusted_av_labels, corrupt
        FROM pe_dumps as pe JOIN ped_vts_mapping as pvm USING(dump_id),
            virus_total_scans as vts
        WHERE dump_id = '%s'
        """ % (dump_id,))
    if cursor.rowcount == 0:
        return
    log_data = list(cursor.fetchone())
    log_data[4] = reorder_domain(log_data[4])

    cursor.execute("""
            SELECT score FROM amico_scores
            WHERE dump_id = %s """, (dump_id, ))
    report = "-"
    if cursor.rowcount > 0:
        score = cursor.fetchone()[0]
        if score is not None:
            if score > amico_threshold:
                report = "MALWARE"
            else:
                report = "BENIGN"
            report += "#%s#%s" % (score, amico_threshold)
    log_data.append(report)

    if log_data:
        #print log_data
        entry = ("PE file download -- timestamp: %s, client_ip: %s, server_ip:"
        " %s, server_port: %s, host: %s, url: %s, referrer: %s, sha1: %s, md5:"
        " %s, file_size: %s, av_labels: %s, corrupt: %s, amico_score: %s" %
            tuple(log_data))
        #     syslog.syslog(syslog.LOG_ALERT,q)
        syslog.syslog(syslog.LOG_WARNING | syslog.LOG_USER, entry)


def main():
    # Wait for db_virus_total to complete
    WAIT_TIME = 60
    time.sleep(WAIT_TIME)

    conn = util.connect_to_db()
    cursor = conn.cursor()
    dump_id = sys.argv[1]
    make_syslog_entry(cursor, dump_id)
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()
