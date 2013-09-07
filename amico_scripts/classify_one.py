##########################################################################
# Copyright (C) 2013 Phani Vadrevu                                        #
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
import sys
import os
import subprocess

import util
from config import *
def main():
    dump_id = sys.argv[1]
    conn = util.connect_to_db()
    cursor = conn.cursor()
    subprocess.call("./classify_one.sh %s %s %s" % 
                      (dump_id, db_user, db_name), shell=True)

    score = None
    with open('rf.test.result', 'r') as f:
        for line in f:
            if ':' in line:
                for word in line.split():
                    if '*' in word:
                        score = word.split(',')[0]
                        if score.startswith('*'):
                            score = score[1:]

    print "AMICO Score:", score
    cursor.execute("INSERT INTO amico_scores VALUES "
                   "(%s, %s)", (dump_id, score))
    subprocess.call("rm rf.test.result", shell=True)
    
if __name__ == "__main__":
    main()
