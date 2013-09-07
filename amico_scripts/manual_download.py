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
import socket
import re
import time
import hashlib
import subprocess
from struct import unpack

import psycopg2
import socks
import urllib2

import config
from config import *

# checks for valid PE header
def is_pe_file(bin_data):

    if not bin_data:
        return False

    if len(bin_data) <= 0:
        return False

    m = re.search('MZ', bin_data)
    if m:
        p = m.start()
        offset = p + unpack('i', bin_data[p+0x3c:p+0x3c+4])[0]
        # print "p=", p, "  offset=", offset
        if bin_data[p:p+2] == 'MZ' and bin_data[offset:offset+2] == 'PE':
            # print "This is a PE file!"
            return True

    print "This is NOT a PE file!"
    return False


# Reorder the subdomains in the host name 
def reorder_domain(host):
    ipreg = re.compile("[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
    host = host.rstrip('.')
    if ipreg.match(host) is None:
        ordered_host = ""
        host += '.'
        domains = re.findall('.*?\.',host)
        for i in range(len(domains)):
            ordered_host += domains[len(domains)-i-1]
        ordered_host = ordered_host[:-1]
        return ordered_host
    else:
        return host

# Take the request, download the file and generate sha1 and md5 hashes
# When the file is a valid pe and different from previous, then, save
# it to the downloads directory
def download_file(req, captured_sha1):
    # Make the request
    try:
        res = urllib2.urlopen(req, timeout=HTTP_TIMEOUT).read()
    except urllib2.URLError, e:
        res = None

    sha1 = None
    md5 = None
    is_pe = None

    if res is None:
        print "Executable could not be downloaded manually"
    else:    
        if is_pe_file(res):
            sha1_obj = hashlib.sha1()
            sha1_obj.update(res)
            sha1 = sha1_obj.hexdigest()

            # Store the downloaded file in a sub directory as md5.exe 
            md5_obj = hashlib.md5()
            md5_obj.update(res)
            md5 = md5_obj.hexdigest()
        
            download_file = open(MAN_DOWNLOAD_DIR+"/"+md5+".exe", "w")
            download_file.write(res)
            download_file.close()
            print "Written " + MAN_DOWNLOAD_DIR + "/" + md5 + ".exe"
            is_pe = True

        else:
            print "Downloaded a non-PE file!"
            is_pe = False

    if captured_sha1 != sha1: 
        different = True 
        print "Checksums did not match for dump_id: ",dump_id
    else:
        different = False

    # Call db_virus_total.py if necessary
    if sha1 is not None and different == True:
        print "Calling virustotal for: {0}".format(sha1)
        p = subprocess.Popen(["python", "db_virus_total.py", sha1, md5])
        time.sleep(VT_TIMEOUT)
        if p.poll() is None:
            p.kill()
        
    return sha1, md5, different, is_pe

def manual_dig(host):
    if not host:
        return None,None,None,None
    p = subprocess.Popen(["dig",host],stdout =subprocess.PIPE)
    dig_data = p.communicate()[0].split('\n')
    ips = []
    cnames = []
    nss = []
    ttls = []
    answer = False
    for line in dig_data:
        if not line:
            continue
        if "ANSWER SECTION" in line:
            answer = True
            continue
        if line[0] == ';':
            if answer: answer = False
            continue
        words = line.split()
        if "A" in words and answer:
            ips.append(words[4])
            ttls.append(words[1])
        if "CNAME" in words and answer:
            cnames.append(reorder_domain(words[4]))
        if "NS" in words:    
            nss.append(reorder_domain(words[4]))

    print ips,ttls,cnames,nss
    return ips,ttls,cnames,nss 

def insert_dig_records(domain,ips,ttls,cnames,nss,cursor):
    if not(ttls and ips and domain):
        return

    # If there is no entry in domain_info for this domain, insert a record
    cursor.execute("""SELECT domain_id,query_volume,max_ttl FROM manual_domain_info
         WHERE domain=%s""",(domain,))
    manual_domain_info = cursor.fetchone()

    if manual_domain_info is None:
        cursor.execute("""
                INSERT INTO manual_domain_info(domain,first_seen,last_seen,
                query_volume,max_ttl) VALUES
                (%s,current_timestamp,current_timestamp,0,0)""",
                (domain,)) 
        cursor.execute("""SELECT domain_id,query_volume,max_ttl FROM manual_domain_info 
                WHERE domain=%s""",(domain,))
        manual_domain_info = cursor.fetchone()

    domain_id = manual_domain_info[0]
    query_volume = manual_domain_info[1]
    max_ttl = manual_domain_info[2]

    for ip,ttl in zip(ips,ttls):
        cursor.execute("""INSERT INTO manual_domain_ips(domain_id,ip,log_date,time)
                         VALUES (%s,%s,current_date,current_timestamp)
                      """,(domain_id,ip))
        if ttl > max_ttl: 
            max_ttl = ttl

    for ns in nss:
        stat = """SELECT insert_if_unique('INSERT INTO manual_domain_ns
                          (domain_id,ns,log_date) VALUES 
                          (%s,\\\'%s\\\',current_date)')"""%(domain_id,ns)
        cursor.execute(stat)
    for cname in cnames:
        stat = """SELECT insert_if_unique('INSERT INTO manual_domain_cnames
                          (domain_id,cname,log_date) VALUES 
                          (%s,\\\'%s\\\',current_date)')"""%(domain_id,cname)
        cursor.execute(stat)

    cursor.execute("""UPDATE manual_domain_info SET last_seen
     =current_timestamp,max_ttl=%s,query_volume=%s 
    WHERE domain_id = %s""",
    (max_ttl,query_volume+1,domain_id))
    

USER_AGENT = "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)"
HTTP_TIMEOUT = 40 # HTTP Request timeout
VT_TIMEOUT = 20 # Timeout for virus total script

# Connect to database
try:
    conn = psycopg2.connect("dbname=%s host=%s user=%s password=%s"
        %(db_name,db_host,db_user,db_password))
except:
    print "Unable to connect to database: "+db_name

# Use Autocommit mode for database connection
conn.set_isolation_level(0)
cursor = conn.cursor()

# Setup the SOCKS proxy
if socks_proxy_host:
    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5,socks_proxy_host,socks_proxy_port)
    socket.socket = socks.socksocket

# Read Arguments
captured_sha1 = sys.argv[1]

# Database query to get the relevant recent record  
cursor.execute("""
    SELECT dump_id,host,url,referer,client,server FROM pe_dumps WHERE sha1 = %s 
        ORDER BY timestamp DESC;""",(captured_sha1,))

row = cursor.fetchone()
dump_id = row[0]
host = row[1]
url = row[2]
referer = row[3]
client = row[4]
server = row[5]
referer_exists = True if referer else False

# If client is a host performing Manual Downloads then exit to prevent
# infinite looping 
if client in man_download_client_ips:
    print "The client:{0} is in man_download_client_ips list,exiting".format(client)
    sys.exit()
    
if host is None:
    host = server

ordered_host = reorder_domain(host)

#ips,ttls,cnames,nss = manual_dig("")
#ips,ttls,cnames,nss = manual_dig(ordered_host)
#insert_dig_records(host,ips,ttls,cnames,nss,cursor)

full_url = "http://"+ ordered_host+ url
#print full_url

# Prepare the urllib2 request
req = urllib2.Request(full_url)
req.add_header("User-Agent",USER_AGENT)
req.add_header("Referer",referer)

download_time = time.time()
sha1, md5, different, is_pe = download_file(req,captured_sha1)

# Database statement
cursor.execute("""
    INSERT INTO manual_download_checksums(dump_id, sha1,
    md5, different, referer_exists, timestamp, is_pe) 
    VALUES (%s, %s, %s, %s, %s, TO_TIMESTAMP(%s), %s)""",
    (dump_id, sha1, md5, different, referer_exists, download_time, is_pe))

# If a referer was present, make another request without referer
if referer_exists:
    # Prepare the urllib2 request
    req = urllib2.Request(full_url)
    req.add_header("User-Agent", USER_AGENT)

    download_time = time.time()
    sha1, md5, different, is_pe = download_file(req, captured_sha1)


    # Database statement
    cursor.execute("""
        INSERT INTO manual_download_checksums(dump_id, sha1,
        md5, different, referer_exists, timestamp, is_pe) 
        VALUES (%s, %s, %s, %s, %s, TO_TIMESTAMP(%s), %s)""",
        (dump_id, sha1, md5, different, False, download_time, is_pe))


cursor.close()
conn.close()

