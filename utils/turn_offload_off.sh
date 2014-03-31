#!/bin/bash

NIC=$1

ethtool -K $NIC tso off
ethtool -K $NIC gso off
ethtool -K $NIC gro off
