#!/bin/bash
dir=models
java -Xmx2000m -cp /usr/share/java/weka.jar weka.classifiers.meta.FilteredClassifier -t $dir/train.arff -d $dir/rf.model -p 1,58,59 -distribution -F "weka.filters.unsupervised.attribute.RemoveType -T string" -W weka.classifiers.trees.RandomForest -- -K 0 -S 1 -I 50 
echo "Finished setting up testing"
