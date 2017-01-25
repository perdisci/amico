import subprocess
import sys
from config import whitelist_subnets, manual_download_ip


def print_usage():
    print "Usage: sudo python start_pe_dump.py ethX"
    sys.exit()

if len(sys.argv) < 2:
    print_usage()
nic = sys.argv[1]

bpf_filter = "\"tcp"

if len(whitelist_subnets) > 0:
    bpf_filter += " and not ("
    for subnet in whitelist_subnets:
        bpf_filter += "net %s or " % (subnet,)
    bpf_filter = bpf_filter[:-4]
    bpf_filter += ")"

if len(manual_download_ip) > 0:
    bpf_filter += " and not net %s" % (manual_download_ip,)

bpf_filter += "\""

subprocess.call("""
        ./file_dump -i %s -d dumps/ -f %s """ %
            (nic, bpf_filter), shell=True)
