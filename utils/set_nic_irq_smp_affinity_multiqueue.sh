#!/bin/bash

# NIC IRQ affinity
# show IRQs for network interfaces
# cat /proc/interrupts | egrep "eth[0-9]+-Tx" 

for i in {119..126}; do echo "Setting IRQ $i"; echo 00000100 > /proc/irq/$i/smp_affinity; done
for i in {129..136}; do echo "Setting IRQ $i"; echo 00000200 > /proc/irq/$i/smp_affinity; done
for i in {155..162}; do echo "Setting IRQ $i"; echo 00000400 > /proc/irq/$i/smp_affinity; done
for i in {164..171}; do echo "Setting IRQ $i"; echo 00000800 > /proc/irq/$i/smp_affinity; done
for i in {190..197}; do echo "Setting IRQ $i"; echo 00001000 > /proc/irq/$i/smp_affinity; done
for i in {199..206}; do echo "Setting IRQ $i"; echo 00002000 > /proc/irq/$i/smp_affinity; done

