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
from config.py import capture_file_types

def prune_http_resp_headers(data):
    # finds start of resp header
    m = re.search("HTTP/\d\.\d\s\d\d\d", data)
    if m:
        pos = m.start()
        data = data[pos:]
        
    # now we can search for the end of the response header
    m = re.search('\r\n\r\n',data)
    if m:
        pos = m.start()
        return data[pos+4:] # returns all data after \r\n\r\n


def is_pe_file(bin_data):
    if bin_data[0:2] == 'MZ':
        offset = unpack('i', bin_data[0x3c:0x3c+4])[0]
        if bin_data[offset:offset+2] == 'PE':
            # print "This is a PE file!"
            return True

    # print "This is NOT a PE file!"
    return False


def is_jar_file(bin_data):
    if bin_data[0:4].encode('hex').upper() == '504B0304':
        # print "Searching for manifest.mf"
        regex = re.compile('MANIFEST.MF',re.IGNORECASE)
        m = regex.search(bin_data)
        if m: 
            # print "Found manifest!"
            return True


def is_apk_file(bin_data):
    if bin_data[0:4].encode('hex').upper() == '504B0304':
        # print "Searching for AndroidManifest.xml"
        regex = re.compile('AndroidManifest.xml',re.IGNORECASE)
        m = regex.search(bin_data)
        if m:
            # print "Found Android Manifest!"
            return True


def is_elf_file(bin_data):
    if bin_data[0].encode('hex').upper() == '7F':
        if bin_data[1:4] == 'ELF':
            return True
    return False 


def is_pdf_file(bin_data):
    if bin_data[0:4] == '%PDF':
        return True
    return False


def is_rar_file(bin_data):
    if bin_data[0:4] == 'Rar!':
        return True
    return False


def is_zip_file(bin_data):
    if bin_data[0:4].encode('hex').upper() == '504B0304':
        return True
    return False


def is_swf_file(bin_data):
    magicstr = bin_data[0:3].encode('hex')
    if magicstr == '465753' or magicstr == '435753' or magicstr == '5A5753':
        return True
    return False


def is_msdoc_file(bin_data):
    # msdocx_magic[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};
    # msdoc_magic[]  = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    magicstr = bin_data[0:8].encode('hex')
    if magicstr == '504B030414000600':
        return True
    if magicstr == 'D0CF11E0A1B11AE1':
        return True
    return False


def is_dmg_file(bin_data):

    magicstr = bin_data[0:1].encode('hex')
    if magicstr == '78' or bin_data[0:3] == 'BZh':
        regex = re.compile('koly',re.IGNORECASE)
        m = regex.search(bin_data)
        if m:
            # print "Found koly!"
            return True
    return False



def extract_file(flow_file, dst=None):

    if not dst:
        dst = flow_file

    f = open(flow_file, 'rb')
    data = f.read()
    f.close()

    data = prune_http_resp_headers(data)

    file_type = None
    file_extension = ''

    if not file_type and is_pe_file(data):
        file_type = "EXE"
        file_extension = "exe"

    if not file_type and is_jar_file(data):
        file_type = "JAR"
        file_extension = "jar"

    if not file_type and is_apk_file(data):
        file_type = "APK"
        file_extension = "apk"

    if not file_type and is_elf_file(data):
        file_type = "ELF"
        file_extension = "elf"

    if not file_type and is_dmg_file(data):
        file_type = "DMG"
        file_extension = "dmg"

    if not file_type and is_msdoc_file(data):
        file_type = "MSDOC"
        file_extension = "msdoc" # generic for DOC(X), PPT(X), XLS(X), etc.

    if not file_type and is_rar_file(data):
        file_type = "RAR"
        file_extension = "rar"

    if not file_type and is_swf_file(data):
        file_type = "SWF"
        file_extension = "swf"

    if not file_type and is_pdf_file(data):
        file_type = "PDF"
        file_extension = "pdf"

    if not file_type and is_zip_file(data): 
        # notice that this is more generic than other 
        # derived file formats (e.g., JAR, DOCX, etc.)
        # and therefore this check should run last!
        file_type = "ZIP"
        file_extension = "zip"

    if file_type in capture_file_types:
        dst = dst+'.'+file_extension 
        print "Writing file:", dst
        f = open(dst, 'wb')
        f.write(data)
        f.close()
        print "Finished!"
        return (file_type, dst, file_extension)

    return(None, None, None)



if __name__ == '__main__':
    extract_file(sys.argv[1])



