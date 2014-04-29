#!/usr/bin/python
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
import os
import config
import re

from config import *
from fe_db_setup import fe_db_setup

# Reorder the subdomains in the host name such that
# the TLD comes first. Eg: com.google.www
def reorder_domain(host):
    host = host.split(':')[0] # in case host string contains port 

    ordered_host = ""
    host += '.'
    domains = re.findall('.*?\.',host)
    for i in range(len(domains)):
        ordered_host += domains[len(domains)-i-1]
    ordered_host = ordered_host[:-1]
    return ordered_host
 
# Connect to database
try:
    conn = psycopg2.connect("dbname=%s host=%s user=%s password=%s"
        %(db_name,db_host,db_user,db_password))
except:
    print "Unable to connect to database: "+db_name

conn.set_isolation_level(0)
cursor = conn.cursor()

try:
    cursor.execute("""
        CREATE TABLE pe_dumps( dump_id SERIAL,PRIMARY KEY(dump_id),
        sha1 VARCHAR(40),md5 VARCHAR(32),timestamp TIMESTAMP, server INET,
        client INET,method VARCHAR(10),url VARCHAR(512),host VARCHAR(256),
        referer VARCHAR(512),server_application VARCHAR(64),
        content_type VARCHAR(128),dst_port INT,corrupt BOOLEAN,file_size INT)
        """)
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("CREATE INDEX pd_sha1_index ON pe_dumps(sha1)")
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("CREATE INDEX pd_md5_index ON pe_dumps(md5)")
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("CREATE INDEX pd_host_index ON pe_dumps(host)")
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("""
        CREATE TABLE virus_total_scans(vt_id SERIAL,PRIMARY KEY(vt_id),
        sha1 VARCHAR(40),md5 VARCHAR(32),json TEXT,num_av_labels INT,
        trusted_av_labels INT,scan_time TIMESTAMP,query_time TIMESTAMP,
        first_seen TIMESTAMP)
        """)
except psycopg2.DatabaseError as e:
    print e

try:
    cursor.execute("""
        CREATE TABLE virus_total_submissions(
            vt_submit_id SERIAL,
            PRIMARY KEY(vt_submit_id),
            submit_time TIMESTAMP,
            sha1 VARCHAR(40),
            md5 VARCHAR(32),
            json TEXT,
            num_av_labels INT,
            trusted_av_labels INT,
            scan_time TIMESTAMP,
            scan_id VARCHAR(75),
            resubmit_id INT REFERENCES virus_total_submissions(vt_submit_id))
        """)
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("""
        CREATE TABLE ped_vts_mapping (dump_id INT REFERENCES pe_dumps(dump_id),
        vt_id INT REFERENCES virus_total_scans(vt_id))
        """)
except psycopg2.DatabaseError as e:
    print e

try:
    cursor.execute("CREATE INDEX vt_sha1_index ON virus_total_scans(sha1)")
except psycopg2.DatabaseError as e:
    print e
try:
    cursor.execute("CREATE INDEX vt_md5_index ON virus_total_scans(md5)")
except psycopg2.DatabaseError as e:
    print e

try:
    cursor.execute("""
        CREATE TABLE manual_download_checksums(dump_id INT REFERENCES pe_dumps(dump_id),
        sha1 VARCHAR(40), md5 VARCHAR(32), different BOOLEAN, referer_exists BOOLEAN,
        timestamp TIMESTAMP, is_pe BOOLEAN);
        """)
except psycopg2.DatabaseError as e:
    print e

try:
    cursor.execute("""
            CREATE TABLE bgp2asn(bgp_prefix INET, as_number INT, as_name VARCHAR(512),
            country_code VARCHAR(2), date_allocated DATE, log_date DATE)
               """)
except psycopg2.DatabaseError as e:
    print e

try:
    cursor.execute("""
        CREATE TABLE amico_scores(
            dump_id INT PRIMARY KEY REFERENCES pe_dumps(dump_id),
            score REAL)
        """)
except psycopg2.DatabaseError as e:
    print e

print("""Created tables: pe_dumps, virus_total_scans, manual_download_checksums,
                         bgp2asn, amico_scores""")

fe_db_setup()
cursor.close()
conn.close()
