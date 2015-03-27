#!/usr/bin/python

# Author: Phani Vadrevu <pvadrevu@uga.edu>

import util
import sys
from config import *

def fe_db_setup():
    conn = util.connect_to_db()
    cursor = conn.cursor()
    
    cursor.execute(""" DROP table if exists features""")
    cursor.execute(""" DROP table if exists weka_features""")
    cursor.execute("""
        CREATE TABLE weka_features(
            dump_id INT,
            raw_dump_num_av_labels INT,
            raw_dump_trusted_av_labels INT,
            vt_month_shelf BOOLEAN,
            corrupt BOOLEAN,
            host_malware_downloads INT,
            host_suspicious_downloads INT,
            host_benign_downloads INT,
            host_total_downloads INT,
            host_malware_ratio REAL,
            host_suspicious_ratio REAL,
            host_benign_ratio REAL,
            host_avg_av_labels REAL,
            host_avg_trusted_labels REAL,
            host_unknown_hashes INT,
            host_total_hashes INT,
            host_unknown_hash_ratio REAL,
            twold_malware_downloads INT,
            twold_suspicious_downloads INT,
            twold_benign_downloads INT,
            twold_total_downloads INT,
            twold_malware_ratio REAL,
            twold_suspicious_ratio REAL,
            twold_benign_ratio REAL,
            twold_avg_av_labels REAL,
            twold_avg_trusted_labels REAL,
            twold_unknown_hashes INT,
            twold_total_hashes INT,
            twold_unknown_hash_ratio REAL,
            server_ip_malware_downloads INT,
            server_ip_suspicious_downloads INT,
            server_ip_benign_downloads INT,
            server_ip_total_downloads INT,
            server_ip_malware_ratio REAL,
            server_ip_suspicious_ratio REAL,
            server_ip_benign_ratio REAL,
            server_ip_avg_av_labels REAL,
            server_ip_avg_trusted_labels REAL,
            server_ip_unknown_hashes INT,
            server_ip_total_hashes INT,
            server_ip_unknown_hash_ratio REAL,
            bgp_malware_downloads INT,
            bgp_suspicious_downloads INT,
            bgp_benign_downloads INT,
            bgp_total_downloads INT,
            bgp_malware_ratio REAL,
            bgp_suspicious_ratio REAL,
            bgp_benign_ratio REAL,
            bgp_avg_av_labels REAL,
            bgp_avg_trusted_labels REAL,
            bgp_unknown_hashes INT,
            bgp_total_hashes INT,
            bgp_unknown_hash_ratio REAL,
            hash_life_time INT,
            num_dumps_with_same_hash INT,
            hash_daily_dump_rate_per_client REAL,
            estimated_clients_with_same_hash INT,
            referer_exists INT,
            host_name_exists INT,
            extension_class VARCHAR(20),
            url_length INT,
            directory_depth INT,
            sha1 VARCHAR(40),
            host VARCHAR(256),
            url_malware_downloads INT,
            url_total_downloads INT,
            url_distinct_sha1s INT,
            url_struct VARCHAR(512),
            url_struct_malware_downloads INT,
            url_struct_total_downloads INT,
            url_struct_distinct_sha1s INT)
            """)

    print "Created weka_features table!"

    conn.commit()
    cursor.close()
    conn.close()

if __name__ == '__main__':
    sys.exit(main())
