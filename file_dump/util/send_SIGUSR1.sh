#!/bin/bash

for i in $(pgrep file_dump); do 
	sudo kill -SIGUSR1 $i; 
done

for i in $(ls zc98_*.log); do 
	tail $i | egrep "(dropped|received)"; 
done
