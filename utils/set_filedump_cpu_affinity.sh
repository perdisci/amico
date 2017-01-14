#!/bin/bash

# CPU affinity for file_dump processes
i=1
for pid in $(ps aux | egrep "\./file_dump" | grep -v sudo | grep -v egrep | awk '{print $2}') 
do 
    sudo taskset -c -p $i $pid 
    let 'i=i+1' 
done

