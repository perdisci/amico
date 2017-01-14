#!/bin/bash

FAMILY=igb

#service udev start

# Remove old modules (if loaded)
rmmod igb
rmmod igb_zc
rmmod pf_ring

echo "CONFIGURING HUGEPAGES"

HUGEPAGES=1024
if [ `cat /proc/mounts | grep hugetlbfs | wc -l` -eq 0 ]; then
	sync && echo 3 > /proc/sys/vm/drop_caches
    # DISABLED! the following hangs when trying to increase number of hugepages to 1024
    # echo $HUGEPAGES > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
fi
AVAILHUGEPAGES=$(grep HugePages_Total /sys/devices/system/node/node0/meminfo | cut -d ':' -f 2|sed 's/ //g')
if [ $AVAILHUGEPAGES -ne $HUGEPAGES ]; then 
	printf "Warning: %s hugepages available, %s requested\n" "$AVAILHUGEPAGES" "$HUGEPAGES"
fi

echo "DONE CONFIGURING HUGEPAGES"

# Note: for hw timestamping on supported adapters compile with make CFLAGS_EXTRA="-DIGB_PTP"

# We assume that you have compiled PF_RING
insmod /var/lib/dkms/pfring/6.5.0/3.2.0-4-amd64/amd64/module/pf_ring.ko
echo "LOADED PF_RING"

# Disable multiqueue
# insmod /var/lib/dkms/igb-zc/5.3.3.5.685/3.2.0-4-amd64/amd64/module/igb.ko RSS=1,1,1,1,1,1,1,1
insmod /var/lib/dkms/igb-zc/5.3.3.5.685/3.2.0-4-amd64/amd64/module/igb_zc.ko RSS=1,1,1,1,1,1,1,1
echo "LOADED igb"

# As many queues as the number of processors
#insmod ./igb.ko RSS=0,0,0,0,0,0,0,0


sleep 1

killall irqbalance 

# MODIFIED to modify settings only for interfacess eth0-eth5
INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ' | egrep 'eth[0-5]$')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"
		ifconfig $IF up
		sleep 1
		
		# Max number of RX slots
		ethtool -G $IF rx 4096

		# Max number of TX slots
		ethtool -G $IF tx 4096
	fi
done
