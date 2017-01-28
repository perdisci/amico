#!/bin/bash

# run as root...

for i in {4,6,8,9,10,11}; do

NIC=eth$i

ifconfig $NIC up
# ethtool -G $NIC rx 4096

ethtool -K $NIC tso off
ethtool -K $NIC gro off
ethtool -K $NIC lro off
ethtool -K $NIC gso off
ethtool -K $NIC rx off
ethtool -K $NIC tx off
ethtool -K $NIC sg off

done
