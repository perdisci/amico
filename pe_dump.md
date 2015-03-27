In this page, we briefly describe how the `pe_dump` process works, and list its command list options.

# Intro #
`pe_dump` is the component of AMICO that performs HTTP flow reconstruction and extract PE files from network traffic.


# Command Line Options #

```

$ ./pe_dump -h

Usage: ./pe_dump [-i NIC] [-r pcap_file] [-A] -d dump_dir [-f "pcap_filter"] [-L lru_cache_size] [-K max_pe_file_size (KB)] [-D debug_level] 

	 -i : Use to specify network interface (e.g., -i eth0)
	 -r : Read from .pcap file instead of NIC (e.g., -r file.pcap)
	 -A : If specified, this flag will turn off the on-the-fly srcIP anonymization
	 -d : Director where raw HTTP respnoses containing reconstructed files are stored (e.g., -d ./dumps
	 -f : Specify BPF filter (e.g., -f "tcp port 80")
	 -L : Change LRU cache size (default = 10000 entries)
	 -K : Change max accepted reconstructed file size, in KB (e.g., -K 1024)
	 -D : Specify debug_level (value from 0-4)

```


# Signals #

**SIGUSR1**

`SIGUSR1` causes pe\_dump to print a number of statistics regarding the packets received, packets lost, cumulative number of tracked TCP flows, number of PE flows observed, etc.

The output should look something like this:

```
----------------------------------
36087298 packets received by filter
0 packets dropped by kernel
161805 number of new half-open (SYN) tcp flows
149535 number of new (SYN ACK) tcp flows
78630 number of new http flows
3 number of new PE flows
----------------------------------
```


**SIGUSR2**

`SIGUSR2` causes pe\_dump to evict stale TCP flows from its LRU cache. All entries with a TTL > MAX\_LRUC\_TTL will be evicted from the cache. If an evicted TCP flow appeared to contain a PE file, the file will be dumped on disk.

The output should look something like this:

```
----------------------------------
LRU cache size (before celaning) = 29968
LRU cache size (after cleaning) = 3060
----------------------------------
```