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

# Postgres DB Info
db_host="localhost"
db_name=""
db_user=""
db_password=""

# VirusTotal API Keys, as a list of Python Strings eg: ["abcd", "efgh"]
vt_keys=[]

# When running AMICO under a SOCKS proxy, use these.
# Else, have socks_proxy_host as "None"
#socks_proxy_host="localhost"
socks_proxy_host=None
socks_proxy_port=12345

trusted_av_vendors=["Avast","AVG","F-Secure","Kaspersky","McAfee","Microsoft","Sophos","Symantec","TrendMicro"]

# Every time a download is detected using the URL from which the executable has
# been downloaded, a new HTTP request is created and the file is refetched from
# the same webserver. We refer to this as a manual download. Please specify the
# directory where these manual downloads should be saved
MAN_DOWNLOAD_DIR = "manual_downloads"

# The IP from which the manual downloads are happening should be listed here to
# prevent infinite loops. 
# Instead, leave this empty and fill the manual download IP (i.e. the IP of the
# machine on which AMICO is running) in the script
# "start_pe_dump.sh" in "pe_dump" directory
man_download_client_ips=[""]
