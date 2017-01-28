#!/bin/bash

# launch as ./util/start.sh

for i in {4,6,8,9,10,11}; do 
    python start_file_dump.py zc:eth$i >& eth$i.log & 
done

sleep 1

./util/set_cpu_affinity.sh 0
