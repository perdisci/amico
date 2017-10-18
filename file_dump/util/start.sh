#!/bin/bash

# launch as ./util/start.sh

for i in {0..8}; do 
    python start_file_dump.py "zc:99@$i" >& zc99_$i.log & 
done

sleep 1

./util/set_cpu_affinity.sh 2
