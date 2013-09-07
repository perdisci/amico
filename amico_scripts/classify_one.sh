#!/bin/bash
##########################################################################
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

if [ $# -eq 0 ]
  then
      echo "No arguments supplied"
      exit 1
  fi

echo '\o rf.test.out \\ select * from weka_features '"where dump_id = $1"|psql -wU $2 $3
./online_psql2arff.py -r rf.test.out -w rf.test.arff -n 1 -t 2 -vs 3 -c 4
java -Xmx2000m -cp /usr/share/java/weka.jar weka.filters.unsupervised.attribute.Remove -R 2,3 -i rf.test.arff -o temp.arff
cp temp.arff rf.test.arff

java -Xmx2000m -cp /usr/share/java/weka.jar weka.classifiers.meta.FilteredClassifier -l rf.model -p 1,58,59 -distribution -T rf.test.arff > rf.test.result
