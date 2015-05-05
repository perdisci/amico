#!/usr/bin/python
#
###########################################################################
# Copyright (C) 2014 Phani Vadrevu                                        #
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
from multiprocessing import Process
import shutil
import os
import subprocess
import hashlib
import time
import traceback

from config import whitelist_domains, vt_submissions as vts_config
from vt_submit import vt_submissions_func
# from pe_extract import pe_extract
from extract_file import extract_file
from db_file_dumps import db_file_dumps
from db_virus_total import db_virus_total
from manual_download import manual_download
from ip2asn import ip2asn
from get_feature_vector import get_feature_vector
from classify_dump import classify_dump
from db_syslog import db_syslog

WAIT_TIME = 1
DUMP_DIR = "../pe_dump/dumps"
RAW_DIR = "parsed/raw_files/"
FILES_DIR = "parsed/captured_files/"
MD_TIMEOUT = 180
VT_TIMEOUT = 60


# Makes a function call in a separate process
# and makes sure it times out after 'timeout' seconds
def process_timeout(func, func_args, timeout):
    p = Process(target=func, args=(func_args,))
    p.start()
    p.join(timeout)
    p.terminate()


def is_whitelisted(file_name):
    with open(file_name) as f:
        for _ in xrange(6):
            line = f.readline()
            if line.startswith("% Host:"):
                for domain in whitelist_domains:
                    if line.rstrip().endswith(domain):
                        return True
                break
    return False


def get_file_hashes(file_path):
    with open(file_path, 'rb') as f:
        cont = f.read()
        sha1 = hashlib.sha1(cont).hexdigest()
        md5 = hashlib.md5(cont).hexdigest()
    file_size = os.stat(file_path).st_size
    return sha1, md5, file_size


def process_file(raw_path, file_name):
    file_type,file_path,file_extension = extract_file(raw_path)
    print "raw_file:", raw_path
    print "file_path:", file_path
    if not file_type:
        print "This is NOT a file of interest! "
        print "Removing raw data from disk:", raw_path
        # remove the related raw file
        os.remove(raw_path)
        print "Removed!"
        return
    print "file_type:", file_type

    # If we are really dealing with a PE file
    sha1, md5, file_size = get_file_hashes(file_path)
    dump_id, corrupt_pe = db_file_dumps(raw_path, sha1, md5, file_size, file_type)

    # query VT
    Process(target=process_timeout,
        args=(db_virus_total, (dump_id,), VT_TIMEOUT)).start()
    if vts_config == "manual": # attempt to re-download the file "manually"
        Process(target=process_timeout,
            args=(manual_download, sha1, MD_TIMEOUT)).start()

    ip2asn(dump_id)
    get_feature_vector(dump_id,file_type)
    classify_dump(dump_id)
    Process(target=db_syslog, args=(dump_id,)).start()
    sha1_path = os.path.join(
            FILES_DIR, "%s.%s" % (sha1,file_extension))
    md5_path = os.path.join(
            FILES_DIR, "%s.%s" % (md5,file_extension))
    shutil.move(file_path, sha1_path)
    print "sha1_path", sha1_path
    print "md5_path", md5_path
    if not os.path.exists(md5_path):
        os.symlink("%s.%s" % (sha1,file_extension), md5_path)
    print "Done processing file: %s" % (raw_path,)


def start_amico():
    Process(target=vt_submissions_func).start()
    print "Started amico_scripts"
    while True:
        p = subprocess.Popen(
                'ls -atr %s |egrep "\:[0-9]+\-[0-9]+$" | egrep -v "\.tmp$"' %
                (DUMP_DIR,),
                stdout=subprocess.PIPE, shell=True)
        output = p.communicate()[0]
        file_names = [i.strip() for i in output.split('\n') if i.strip() != '']
        for file_name in file_names:
            file_path = os.path.join(DUMP_DIR, file_name)
            if not is_whitelisted(file_path):
                raw_path = os.path.join(RAW_DIR, file_name)
                shutil.copy(file_path, RAW_DIR)
                try:
                    process_file(raw_path, file_name)
                except Exception as e:
                    print "Exception in processing file %s" % (raw_path,)
                    print e
                    traceback.print_exc()
            else:
                print "domain in %s is whitelisted. Ignoring..." % (file_path,)
            os.remove(file_path)
        time.sleep(WAIT_TIME)

if __name__ == "__main__":
    start_amico()
