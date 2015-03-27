These are the steps we use to tune the system for better packet capture, which in our experience dramatically decrease packet loss (using this [example deployment](https://code.google.com/p/amico/wiki/Deployment), we are able to significantly lower packet loss for traffic between 3.5Gbps to 4.5Gbps without using PF\_RING).


# Steps #

Follow these steps (tested on Debian Wheezy running on a Dell PowerEdge with 16 CPU cores):
  * Turn network offloading off. You can use our script [turn\_offload\_off.sh](https://code.google.com/p/amico/source/browse/trunk/utils/turn_offload_off.sh) (see also [Wireshark Capture Setup](http://wiki.wireshark.org/CaptureSetup/Offloading))
  * Set IRQ affinity for each of your NICs and possible Rx queues per NIC. You can use [set\_nic\_irq\_smp\_affinity\_multiqueue.sh](https://code.google.com/p/amico/source/browse/trunk/utils/set_nic_irq_smp_affinity_multiqueue.sh)
  * Pin each `pe_dump` process to a different CPU. For this you can use [set\_pedump\_cpu\_affinity.sh](https://code.google.com/p/amico/source/browse/trunk/utils/set_pedump_cpu_affinity.sh)

# PF\_RING #

If you want to try PF\_RING, you could follow our  [quick guidelines](https://code.google.com/p/amico/source/browse/trunk/external_libs/README). However, notice that we found that there seems to be a serious bug in PF\_RING-6.0.1 and/or the modified Intel igb driver that comes with it. This may cause rare but annoying kernel panic events (it occurred with Kernel version: Linux 3.2.0-4-amd64 #1 SMP Debian 3.2.60-1+deb7u3 x86\_64 GNU/Linux)

With `PF_RING` it should be possible to use one 10Gbps interface, and create virtual (sub) interfaces on which to attach your multiple instances of `pe_dump`. This can be done using `PF_RING`'s [zbalance\_ipc](http://www.ntop.org/pf_ring/how-to-promote-scalability-with-pf_ring-zc-and-n2disk/) (we have not tested this...)

