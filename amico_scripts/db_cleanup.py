#!/usr/bin/env python

# Author: Phani Vadrevu <pvadrevu@uga.edu>

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
