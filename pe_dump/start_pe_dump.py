
# Authors: Phani Vadrevu <pvadrevu@uga.edu>
#          Roberto Perdisci <perdisci@cs.uga.edu>

import subprocess
import argparse
from config import whitelist_subnets, manual_download_ip

"""A simple Python script that builds a BPF filter string from the
   whitelist subnets mentioned in config.py and call the pe_dump program in turn
"""

def build_parser():
    parser = argparse.ArgumentParser(description='Start pe_dump process on a given NIC')
    parser.add_argument('--anonymize', '-A', action='store_true',
                        help='If specified, this flag will turn off the on-the-fly srcIP anonymization')
    parser.add_argument('--max_pe_file_size', '-K',
                        help='Change max accepted reconstructed file size, in KB (default= -K 2048)')
    parser.add_argument('--lru_cache_size', '-L',
                        help='Change LRU cache size (default=10000 entries)')
    parser.add_argument('NIC', help='Use to specify network interface (e.g., eth0)')
    return parser

def get_bpf_filter():
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
    return bpf_filter


def get_pe_dump_cmd(args, bpf_filter):
    cmd = "sudo ./pe_dump -d dumps/ "
    if args.anonymize:
        cmd += "-A "
    if args.max_pe_file_size:
        cmd += "-K %s " % (args.max_pe_file_size,)
    if args.lru_cache_size:
        cmd += "-L %s " % (args.lru_cache_size,)
    cmd += "-f %s -i %s" % (bpf_filter, args.NIC)
    return cmd


def main():
    parser = build_parser()
    args = parser.parse_args()
    bpf_filter = get_bpf_filter()
    cmd = get_pe_dump_cmd(args, bpf_filter)
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    main()
