
# Author: Phani Vadrevu <pvadrevu@uga.edu>

"""
A script to make a copy of the pe_dumps table with anonymized client IPs
"""
import random
import sys
sys.path.insert(0, '../amico_scripts')

import util

FIRST_OCTET = '192'


def anonymize_ip(ip, key_bytes):
    ip_octets = ip.split('.')[1:]
    anony_ip_octets = [FIRST_OCTET]
    anony_ip_octets.extend(
           [str(key ^ int(octet))
            for (key, octet) in zip(key_bytes, ip_octets)])
    return '.'.join(anony_ip_octets)


def drawProgressBar(percent, barLen=60):
    sys.stdout.write("\r")
    progress = ""
    for i in range(barLen):
        if i <= int(barLen * percent):
            progress += "="
        else:
            progress += " "
    sys.stdout.write("[%s] %.2f%%" % (progress, percent * 100))
    sys.stdout.flush()


def main():
    key_bytes = [random.randint(0, 255) for _ in range(3)]
    conn = util.connect_to_db()
    cursor = conn.cursor()
    cursor.execute("""
        DROP TABLE IF EXISTS pe_dumps_copy """)
    cursor.execute("""
        CREATE TABLE pe_dumps_copy AS TABLE pe_dumps """)
    cursor.execute("""
        SELECT DISTINCT client
        FROM pe_dumps_copy
        """)

    orig_clients = [row[0] for row in cursor.fetchall()]
    anony_clients = {}
    num_ips = len(orig_clients)
    for ip in orig_clients:
        anony_clients[ip] = anonymize_ip(ip, key_bytes)
    past_progress = 0
    for i, ip in enumerate(anony_clients):
        progress = round((float(i) / num_ips), 2)
        if progress > past_progress:
            drawProgressBar(progress)
        past_progress = progress
        cursor.execute("""
            UPDATE pe_dumps_copy
            SET client = %s
            WHERE client = %s
            """, (anony_clients[ip], ip))
    print "\n Made a copy of pe_dumps table with anonymized client IPs!!"
    cursor.close()
    conn.close()


if __name__ == "__main__":
    main()
    #key_bytes = [random.randint(0, 255) for _ in range(3)]
    #print "key_bytes:", key_bytes
    #print anonymize_ip('1.1.1.1', key_bytes)
