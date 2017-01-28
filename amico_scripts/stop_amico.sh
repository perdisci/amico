#!/bin/bash

for i in $(ps ux | grep start_amico.py | grep -v grep | awk '{print $2}'); do 
    kill $i; 
done
