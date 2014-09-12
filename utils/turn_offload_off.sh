#!/bin/bash

# run as root...

NIC=$1

ifconfig $NIC down
ifconfig $NIC up
ethtool -G ethX rx 4096

ethtool -K $NIC tso off
ethtool -K $NIC gro off
ethtool -K $NIC lro off
ethtool -K $NIC gso off
ethtool -K $NIC rx off
ethtool -K $NIC tx off
ethtool -K $NIC sg off
