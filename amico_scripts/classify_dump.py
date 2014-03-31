#! /usr/bin/python
###########################################################################
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
import subprocess

import psycopg2.extras

import util
from features import features
from config import model_file

output_file = "test.arff"


def print_arff(dump_id):
    conn = util.connect_to_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)
    cursor.execute("""
        SELECT * FROM weka_features
        WHERE dump_id = %s""",
        (dump_id, ))
    if cursor.rowcount == 0:
        print "Feature vector not found. Exiting..."
        sys.exit()
    res = cursor.fetchone()
    res = res._asdict()
    del res['raw_dump_num_av_labels']
    del res['raw_dump_trusted_av_labels']

    w = open(output_file, 'w')
    w.write('@RELATION test\n\n')
    values = []
    for feature in features:
        if feature in ['sha1', 'dump_id', 'host', 'corrupt', 'vt_month_shelf',
                'url_struct']:
            data_type = "STRING"
        elif feature == "extension_class":
            data_type = ("{common_ext,unknown_ext,common_fake,other_ext,"
                   "no_url,no_ext}")
        else:
            data_type = "NUMERIC"
        w.write('@ATTRIBUTE %s %s\n' % (feature, data_type))
        values.append(res[feature])
        #print "%s : %s" % (key, res[key])

    w.write('@ATTRIBUTE class {pos, neg}\n\n')
    w.write('@DATA\n\n')
    try:
        data_string = ','.join(['?' if value is None else str(value) for value
            in values])
    except Exception as e:
        print "Error in writing feature vector to file!", e
    else:
        data_string += ",?"
        w.write(data_string + '\n')
    w.close()
    cursor.close()
    conn.close()


def classify_dump(dump_id):
    print_arff(dump_id)
    subprocess.call(
            "java -Xmx2000m -cp ./weka.jar "
            "weka.classifiers.meta.FilteredClassifier "
            "-l %s -p 1,58,59 -distribution -T test.arff "
            "> test.result" % (model_file,), shell=True)

    conn = util.connect_to_db()
    cursor = conn.cursor()

    score = None
    with open('test.result', 'r') as f:
        for line in f:
            if ':' in line:
                for word in line.split():
                    if '*' in word:
                        score = word.split(',')[0]
                        if score.startswith('*'):
                            score = score[1:]

    print "AMICO Score:", score

    cursor.execute("""
            DELETE FROM amico_scores
            WHERE dump_id = %s""",
            (dump_id, ))
    cursor.execute("INSERT INTO amico_scores VALUES "
                   "(%s, %s)", (dump_id, score))

    #subprocess.call("rm test.arff", shell=True)
    subprocess.call("rm test.result", shell=True)

if __name__ == "__main__":
    dump_id = int(sys.argv[1])
    #print_arff(dump_id)  # For testing
    classify_dump(dump_id)
