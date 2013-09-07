###########################################################################
# Copyright (C) 2012 Phani Vadrevu                                        #
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
import ConfigParser
from datetime import timedelta as td

from util import connect_to_db
from config import *

"""
Create weka_features_train give weka_features and clean_av_labels tables
"""
config = ConfigParser.RawConfigParser()
config.read('config.cfg')
training_period_days = config.getint('classifier', 'training_period_days')


def main():
    train_delta = td(days=training_period_days)
    conn = connect_to_db()
    cursor = conn.cursor()
    create_train_set(cursor, train_delta)
    cursor.close()
    conn.close()


def create_train_set(cursor, train_delta):
    cursor.execute("DROP table if exists weka_features_train")

    cursor.execute("CREATE table weka_features_train(LIKE weka_features)")
    cursor.execute("""INSERT INTO weka_features_train
                  (SELECT * FROM weka_features where corrupt='f' and
                    sha1 in (SELECT sha1 from clean_vt_labels))""")
    cursor.execute("""DELETE from weka_features_train WHERE dump_id < 6000""")
    cursor.execute("""alter table weka_features_train rename column raw_dump_num_av_labels to clean_nav_labels""")
    cursor.execute("""alter table weka_features_train rename column raw_dump_trusted_av_labels to clean_tav_labels""")
    cursor.execute("""update weka_features_train as wfc set clean_nav_labels= cvl.num_av_labels, 
                        clean_tav_labels=cvl.trusted_av_labels
                        from clean_vt_labels as cvl
                        where cvl.sha1=wfc.sha1""")
    cursor.execute("""select MIN(timestamp) from weka_features_train join pe_dumps using(dump_id)""")
    min_timestamp = cursor.fetchone()[0]
    train_test_divide = min_timestamp + train_delta
    print train_test_divide
    cursor.execute("""DELETE from weka_features_train as wft
                      USING pe_dumps as pe 
                      WHERE pe.dump_id = wft.dump_id and 
                            timestamp > %s""",
                                           (train_test_divide,))
if __name__ == "__main__":
    main()
