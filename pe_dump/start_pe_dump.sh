#!/bin/bash

# This script launches pe_dump with a BPF filter and excludes traffic to
# popular sites, such as Google, Facebook, MSN, etc. (see README). 

NIC=$1 # the network interface to sniff from
	
mkdir -p ./dumps

# Please also add the IP address of the machine running AMICO to this BPF
# filter. This prevents unending cycle of PE monitor/download/monitor events
# caused due to AMICO performing manual downloads. See config.py for more
# For example: "tcp and not host x.x.x.x and not (net 69.171..../23)".  
sudo ./pe_dump -i $NIC -d dumps/ -f "tcp and not (net 69.171.224.0/20 or net 66.220.152.0/21 or net 74.125.0.0/16 or net 220.181.111.0/24 or net 123.125.114.0/24 or net 199.59.148.0/22 or net 65.54.94.0/23 or net 65.55.160.0/19 or net 65.55.192.0/18 or net 66.135.192.0/19 or net 157.166.224.0/20 or net 15.192.0.0/16 or net 143.166.0.0/17 or net 17.148.0.0/14 or net 192.150.16.0/23)" -A

# -A flag above anonymizes the Client IPs
# -d indicates dump directory
