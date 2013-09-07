#!/bin/bash
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
if [ $# -ne 2 ]
  then
      echo "Plz give 2 arguments: db_user & db_name"
      exit 1
  fi
dir=models

mkdir -p $dir
echo "\o $dir/train.out "'\\ select * from weka_features_train'|psql -wU $1 $2
echo "Dumped train psql outputs in $dir"

./psql2arff.py -r $dir/train.out -w $dir/train.arff -n 1 -t 2 -vs 3 -c 4
./arff_balancer.py -r $dir/train.arff -c pos neg unknown corrupt_pos corrupt_neg corrupt_unknown -i 1 1 -2 -2 -2 -2
mv $dir/train.bal.arff $dir/train.arff

java -Xmx2000m -cp /usr/share/java/weka.jar weka.filters.unsupervised.attribute.Remove -R 2,3 -i $dir/train.arff -o $dir/temp.arff
mv $dir/temp.arff $dir/train.arff

echo "Created train dataset"
