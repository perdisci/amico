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
db_host = "localhost"
#db_name = "pe_dump_db_oct_01_2013"
db_name = "admin_db_nov_18_2013"
db_user = "pe_dumper"
db_password = "$P3-Dump-1T!"

# VirusTotal API Keys, as a list of Python Strings eg: ["abcd", "efgh"]
# Get your VT API key at: https://www.virustotal.com/en/
vt_keys = ["e7d68df8950c23675507ff75f97077faf53bca446099191c6ad14eb8d27a631c",
                  "60eb1eff1aa3298f3f239cafd7067362e7c9d2ee76bd5cc57c923d363bc2f6de"]

# When running AMICO under a SOCKS proxy, use these.
# Else, have socks_proxy_host as "None"
#socks_proxy_host = "localhost"
socks_proxy_host = None
socks_proxy_port = 12345

trusted_av_vendors = ["Avast", "AVG", "F-Secure", "Kaspersky", "McAfee",
                    "Microsoft", "Sophos", "Symantec", "TrendMicro"]

# The threshold value for classification between (0,1)
# used in db_syslog.py script
amico_threshold = 0.4

# The name of the training model file to be used for
# classification. Use the trainer.py script to create
# a new model specific to your network
#model_file = "models/default.model"
model_file = "models/Mar31_14_091713.model"


LOG_CONF_FILE = "logging.conf"

whitelist = {"se.360.cn", "adobe.com", "apple.com", "avg.com", "dell.com",
             "google.com", "microsoft.com", "windowsupdate.com"}


# Example: training_start_date = "2014-01-01" 
# If left as None, all the download events from the beginning are 
# used for training the classifier
training_start_date = None
# If left as None, all the download events till the end are used
# for training the classifier
#training_days = 5
training_days = None

# "live", "manual" or None
#vt_submissions = "manual"
vt_submissions = "live"
#vt_submissions = None

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
man_download_client_ips = [""]
