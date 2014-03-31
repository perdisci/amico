#!/usr/bin/env python

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

import psycopg2
import config
from config import *

# Connect to database
try:
    conn = psycopg2.connect("dbname=%s host=%s user=%s password=%s"
        %(db_name,db_host,db_user,db_password))
except:
    print "Unable to connect to database: "+db_name

# Use Autocommit mode for database connection
conn.set_isolation_level(0)
cursor = conn.cursor()

cursor.execute("""DROP TABLE IF EXISTS pe_dumps,virus_total_scans,
        ped_vts_mapping, manual_download_checksums,bgp2asn,
        weka_features, virus_total_submissions, amico_scores CASCADE""")
print """Dropped the tables: pe_dumps,virus_total_scans,domain_whitelist,
        manual_download_checksums,bgp2asn, virus_total_submissions,
        amico_scores, weka_features, ped_vts_mapping"""
cursor.close()
conn.close()
