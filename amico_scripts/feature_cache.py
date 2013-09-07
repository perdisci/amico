##########################################################################
# Copyright (C) 2012 Phani Vadrevu                                        #
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
from datetime import timedelta
"""
This script enables copying features instead of re-measuring them if 
same download is seen with in a specific time interval. 
This is called from db_pe_dumps.py
"""

CACHE_INTERVAL = 60 * 60 * 6
delta = timedelta(seconds=CACHE_INTERVAL) 

def check_feature_exists(cursor, dump_id, host, sha1):
    cursor.execute("""
          SELECT * from pe_dumps where host = %s and
          sha1 = %s and
          dump_id < %s and
          current_timestamp - timestamp < %s""",
          (host, sha1, dump_id, delta))
    if cursor.rowcount > 0:
        return True
    return False

def copy_features(cursor, dump_id, host, sha1):
    cursor.execute("""
          SELECT dump_id from pe_dumps where host = %s and
          sha1 = %s and
          dump_id < %s and
          current_timestamp - timestamp < %s 
          ORDER BY dump_id DESC LIMIT 1""",
          (host, sha1, dump_id, delta))
    old_dump_id = cursor.fetchone()[0]

    cursor.execute("""
           CREATE TABLE temp (LIKE features)""")
    cursor.execute("""
           INSERT INTO temp 
           SElECT * from features
           WHERE dump_id = %s""", (old_dump_id,))
    cursor.execute("""
           UPDATE temp 
           SET dump_id = %s""", (dump_id,))
    cursor.execute("""
           INSERT INTO features
           SELECT * from temp""")
    cursor.execute("DROP TABLE temp")
