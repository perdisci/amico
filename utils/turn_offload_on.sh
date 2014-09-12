#!/bin/bash

# run as root...

NIC=$1

ethtool -K $NIC tso on
ethtool -K $NIC gro on
ethtool -K $NIC lro on
ethtool -K $NIC gso on
ethtool -K $NIC rx on
ethtool -K $NIC tx on
ethtool -K $NIC sg on
