#!/bin/bash
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
# this is necessary because sometimes the VT API hangs and waists lost of CPU

TIMEOUT=15

while true; do
  ps ux | grep db_virus_total.py | grep python | awk '{print $2}' > pids_vt.tmp
  sleep $TIMEOUT
  for pid in $(cat pids_vt.tmp); do
    echo "killing $pid"
    kill -9 $pid
  done
  rm pids_vt.tmp
done
