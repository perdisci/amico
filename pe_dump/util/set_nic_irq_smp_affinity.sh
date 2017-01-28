#!/bin/bash

# NIC IRQ affinity
# show IRQs for network interfaces
# cat /proc/interrupts | egrep "eth[0-9]+-Tx" 

### the IRQ numbers need to be replaced with the correct ones!
sudo echo 00000100 > /proc/irq/119/smp_affinity
sudo echo 00000200 > /proc/irq/121/smp_affinity
sudo echo 00000400 > /proc/irq/123/smp_affinity
sudo echo 00000800 > /proc/irq/125/smp_affinity
sudo echo 00001000 > /proc/irq/128/smp_affinity
sudo echo 00002000 > /proc/irq/130/smp_affinity
