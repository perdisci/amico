#!/bin/bash

NIC=$1 # the network interface to sniff from
NET=$2 # the subnetwork to monitor
	
mkdir -p ./dumps

sudo ./pe_dump -i $NIC -d dumps/ -f "tcp"

########
########
#
# this script launches pe_dump with a BPF filter that excludes the IP address used to perform manual downloads (x.x.x.x), and that excludes traffic to popular sites, such as Google, Facebook, MSN, etc. (see README) 
#
#sudo ./pe_dump -i $NIC -d dumps/ -f "tcp and not host x.x.x.x and not (net 69.171.224.0/20 or net 66.220.152.0/21 or net 74.125.0.0/16 or net 220.181.111.0/24 or net 123.125.114.0/24 or net 199.59.148.0/22 or net 65.54.94.0/23 or net 65.55.160.0/19 or net 65.55.192.0/18 or net 66.135.192.0/19 or net 157.166.224.0/20 or net 15.192.0.0/16 or net 143.166.0.0/17 or net 17.148.0.0/14 or net 192.150.16.0/23)" 
#
#sudo ./pe_dump -i $NIC -d dumps/ -f "tcp" -A
