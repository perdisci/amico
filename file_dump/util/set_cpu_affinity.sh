#!/bin/bash

# CPU affinity for pe_dump processes
i=$1
for pid in $(ps aux | egrep "\./file_dump" | grep -v sudo | grep -v "bin/sh" | grep -v grep | awk '{print $2}') 
do 
    taskset -c -p $i $pid 
    let 'i=i+1' 
done
