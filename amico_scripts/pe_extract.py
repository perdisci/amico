#!/usr/bin/python

###########################################################################
# Copyright (C) 2011 Roberto Perdisci                                     #
# perdisci@cs.uga.edu                                                     #
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

import sys, os
import re
from struct import unpack

def prune_http_resp_headers(data):
    # this makes sure we find the actual start of the PE and not a random match
    m = re.search('\s\sMZ', data)
    if m:
        pos = m.start()
        data = data[pos:]
        
    # now we can start copyting data from MZ to the end
    m = re.search('MZ',data)
    if m:
        pos = m.start()
        return data[pos:]

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


def usage():
    print >> sys.stderr, 'usage: %s [-i device] [-r file] [pcap filter]' % sys.argv[0]
    sys.exit(1)


def main():
    flow_file = sys.argv[1]
    f = open(flow_file, 'rb')
    data = f.read()
    f.close()

    data = prune_http_resp_headers(data)

    if is_pe_file(data):
        print "Writing file:", flow_file+'.exe'
        f = open(flow_file+'.exe', 'wb')
        f.write(data)
        f.close()

    print "Finished!"



if __name__ == '__main__':
    main()
