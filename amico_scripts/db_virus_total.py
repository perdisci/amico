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
import socket
import random
from datetime import datetime, timedelta, MINYEAR

import psycopg2
#from bs4 import BeautifulSoup
import simplejson
import urllib
import urllib2
import socks
import ssl

import config
from config import *

# Do not make a new query for the same sha1 if the previous query was made
# with in VT_QUERY_INTERVAL (in days)
VT_QUERY_INTERVAL = 1

def get_report_from_vt(file_hash):
    try:
        return urllib2.urlopen('https://www.virustotal.com/file/%s/analysis/'
                            % (file_hash,), None, 20).read()
    except (urllib2.URLError, ssl.SSLError) as e:
        print "Exception: %s" % (e,)
        return None

def get_first_seen(html):
    soup = BeautifulSoup(html)
    #tag = soup.find_all(text=re.compile('First seen by VirusTotal'))
    tag = soup.find_all(text='First seen by VirusTotal')
    if len(tag) == 0:
        match = re.search('First seen by VirusTotal(.*?)UTC', html, flags=re.DOTALL)
        if match is None:
            print "its empty!"
            return
        first_seen = " ".join(match.group(1).strip().split()[1:3])
        return first_seen 
    else:
        first_seen = tag[0].parent.parent.contents[2]
        first_seen = " ".join(first_seen.split()[:2])
        return first_seen
    """
    if len(time_tag) > 0:
        scan_time = time_tag[0].parent.parent.contents[3].string
        scan_time = scan_time.encode('ascii', 'ignore')
        scan_time = scan_time.split()
        scan_time = scan_time[0] + " " + scan_time[1]
    else:
        return None, None, None, None
    table = soup.find_all('table', attrs={'id':'antivirus-results'})
    if len(table) > 0:
        table = table[0].tbody
    else:
        return None, None, None, None
    tags = table.find_all('tr')[1:]

    num_av_labels = 0
    num_trusted_av_labels = 0
    av_labels = {}

    for tag in tags:
        tds = tag.find_all('td')
        
        av_vendor = tds[0].string.encode('ascii', 'ignore')
        if tds[1].string != '-' and tds[1].string:
            av_label = tds[1].string.encode('ascii', 'ignore')
            av_labels[av_vendor] = av_label
            #print tds[1].string
            num_av_labels += 1
            if tds[0].string in trusted_av_vendors:
                num_trusted_av_labels += 1
        else:
            av_labels[av_vendor] = ""
            

    json_dict = {}
    json_dict["report"] = [scan_time, av_labels]
    json_text = json.dumps(json_dict)
    return num_av_labels, num_trusted_av_labels, json_text, scan_time
    """

def get_vt_key():
    random.seed()
    k = random.randint(0,len(vt_keys)-1)
    print "Using VT API key number", k
    return vt_keys[k] # vt_keys must be a list of valid virust_total API keys
    

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
md5 = sys.argv[2]
dump_id = sys.argv[3]

# Exit if this sha1 has been queried in the past VT_QUERY_INTERVAL period
prev_query_time = datetime(MINYEAR, 1, 1, 0, 0, 0, 0)
time_now = datetime.now()
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
        
# Setup SOCKS proxy
if socks_proxy_host:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,socks_proxy_host,socks_proxy_port);
    socket.socket = socks.socksocket
###

# Send the request
url = "https://www.virustotal.com/api/get_file_report.json"
parameters = {"resource": sys.argv[1],"key":get_vt_key()}
data = urllib.urlencode(parameters)
req = urllib2.Request(url, data)

# Read the response
try:
    response = urllib2.urlopen(req)
except:
    print "db_virus_total.py: Error accessing virustotal.com"
    sys.exit()

json = response.read()
response_dict = simplejson.loads(json)
result = response_dict.get("result")
report = response_dict.get("report")

if result == 1:
    scan_time = report[0]
    scan_time = scan_time + " UTC"
    scans = report[1]
    num_av_labels = 0
    trusted_av_labels = 0
    for k,v in scans.iteritems():
        if v :
            num_av_labels += 1
            if k in trusted_av_vendors: trusted_av_labels += 1

    # Removed as we are getting a 403 for urllib requests
    html = get_report_from_vt(sha1)
    #permalink = json_dict['permalink']
    #print "sha1:", sha1, permalink
    ##print permalink
    #html = get_html_from_vt(permalink)
    if html is None:
        print "No reply from VirusTotal"
    else:
        first_seen = get_first_seen(html)
        if first_seen is None:
            print "No first seen in the report"

    # Database statement
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

elif result == 0:
    # Database statement
    cursor.execute("""
            INSERT INTO virus_total_scans(sha1,md5,query_time)
            VALUES (%s,%s,CLOCK_TIMESTAMP())
            """,(sha1,md5))
    print "Virus Total: No scan report exists in the VT database"

elif result == -2:
    print "Virus Total: API Query limit reached"

cursor.close()
conn.close()
