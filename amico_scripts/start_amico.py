from multiprocessing import Process
import shutil
import os
import subprocess
import hashlib
import time
import traceback

from config import whitelist_domains, vt_submissions as vts_config
from vt_submissions import vt_submissions
from pe_extract import pe_extract
from db_pe_dumps import db_pe_dumps
from db_virus_total import db_virus_total
from manual_download import manual_download
from ip2asn import ip2asn
from get_feature_vector import get_feature_vector
from classify_dump import classify_dump
from db_syslog import db_syslog

WAIT_TIME = 1
DUMP_DIR = "../pe_dump/dumps"
RAW_DIR = "parsed/raw_files/"
PE_DIR = "parsed/pe_files/"
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
    exe_path = os.path.join(
            PE_DIR, "%s.exe" % (file_name,))
    print "raw_file", raw_path
    print "exe_path", exe_path
    pe_extract(raw_path, exe_path)
    sha1, md5, file_size = get_file_hashes(exe_path)
    dump_id, corrupt_pe = db_pe_dumps(raw_path, sha1, md5, file_size)
    if not corrupt_pe:
        Process(target=process_timeout,
            args=(db_virus_total, (dump_id,), VT_TIMEOUT)).start()
    if vts_config == "manual":
        Process(target=process_timeout,
            args=(manual_download, (dump_id,), MD_TIMEOUT)).start()
    ip2asn(dump_id)
    get_feature_vector(dump_id)
    classify_dump(dump_id)
    Process(target=db_syslog, args=(dump_id,)).start()
    sha1_path = os.path.join(
            PE_DIR, "%s.exe" % (sha1,))
    md5_path = os.path.join(
            PE_DIR, "%s.exe" % (md5,))
    shutil.move(exe_path, sha1_path)
    print "sha1_path", sha1_path
    print "md5_path", md5_path
    if not os.path.exists(md5_path):
        print "os.path.exists(md5_path)", os.path.exists(md5_path)
        os.symlink("%s.exe" % (sha1,), md5_path)
    print "Done processing file: %s" % (raw_path,)


def start_amico():
    Process(target=vt_submissions).start()
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
