#!/bin/bash

for i in $(ps aux | egrep "root" | egrep "pe_dump -i eth" | egrep -v "sudo" | awk '{print $2}'); do sudo kill -SIGTERM $i; done
