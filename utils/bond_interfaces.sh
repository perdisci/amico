#!/bin/bash

# sudo apt-get install ifenslave
sudo modprobe bonding
sudo ifconfig bond0 up
sudo ifenslave bond0 eth2 eth3 eth4 eth5
# sudo /sbin/vconfig add bond0 20
