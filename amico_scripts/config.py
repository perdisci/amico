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

man_download_client_ips=[""]
MAN_DOWNLOAD_DIR = "manual_downloads"
