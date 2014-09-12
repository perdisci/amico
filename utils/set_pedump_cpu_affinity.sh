#!/bin/bash

# CPU affinity for pe_dump processes
i=1
for pid in $(ps aux | egrep "\./pe_dump" | grep -v sudo | grep -v egrep | awk '{print $2}') 
do 
    sudo taskset -c -p $i $pid 
    let 'i=i+1' 
done

