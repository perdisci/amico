#!/bin/bash

for i in $(ps aux | grep file_dump | grep -v python | grep -v sudo | grep -v postgres | grep -v grep | awk '{print $2}'); do 
	sudo kill -SIGUSR1 $i; 
done

for i in $(ls eth*.log); do 
	tail $i | egrep "(dropped|received)"; 
done
