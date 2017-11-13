/**
 ***************************************************************************
 * Copyright (C) 2011, Roberto Perdisci                                    *
 * perdisci@cs.uga.edu                                                     *
 *                                                                         *
 * Distributed under the GNU Public License                                *
 * http://www.gnu.org/licenses/gpl.txt                                     *   
 *                                                                         *
 * This program is free software; you can redistribute it and/or modify    *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation; either version 2 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 ***************************************************************************
 */


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "lru-cache.h"
#include "seq_list.h"

#include "ghash_table.h" // new generic hash table
#include "glru_cache.h"  // new implementation of O(1) LRU cache
#include "fifo_queue.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define ETH_ADDR_LEN  6
#define ETH_VLAN_HDR_LEN 4
#define ETH_HEADER_LEN 14 // lenght of the "standard" ethernet frame
#define ETH_BASE_FRAME_LEN 1514
#define PCAP_SNAPLEN ETH_BASE_FRAME_LEN+ETH_VLAN_HDR_LEN // increased to cover corener cases with eth.len > 1514 (e.g., in case of VLAN tags)
// #define PCAP_SNAPLEN 65535 // increased to cover jumbo frames! this makes things very slow!
#define MAX_RCV_PACKETS -1


/////////////////////////
// Definition of Packet Headers

/* Ethernet header */
struct eth_header {
        u_char  eth_dhost[ETH_ADDR_LEN]; 
        u_char  eth_shost[ETH_ADDR_LEN]; 
        u_short eth_type;              
};

/* Ethernet header including VLAN tag */
struct eth_vlan_header {
        u_char  eth_dhost[ETH_ADDR_LEN];
        u_char  eth_shost[ETH_ADDR_LEN];
        u_char  eth_vlan_hdr[ETH_VLAN_HDR_LEN];
        u_short eth_type;
};

/* IP header */
struct ip_header {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HEADER_LEN(ip)   (((ip)->ip_vhl) & 0x0f)
#define IP_VER(ip)          (((ip)->ip_vhl) >> 4)

struct tcp_header {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */

        u_int th_seq;                   /* sequence number */
        u_int th_ack;                   /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
/////////////////////////


/////////////////////////
// The following constants are used to mark the state of the reconstructed HTTP flows
// not all of the following FLOW_* constant are used 
#define FLOW_INIT 0
#define FLOW_SYNACK 1
#define FLOW_HTTP 2
#define FLOW_NOT_HTTP -2
#define FLOW_HTTP_RESP_HEADER_WAIT 3
#define FLOW_HTTP_RESP_HEADER_COMPLETE 4
#define FLOW_HTTP_RESP_MAGIC_WAIT 5
#define FLOW_HTTP_RESP_MAGIC_FOUND 6
#define FLOW_HTTP_RESP_MAGIC_NOT_FOUND -6
#define FLOW_FILE_DUMP 7
#define FLOW_FILE_RESET -7

#define FILE_FOUND 1 // Possible interesting file found 
#define FILE_NOT_FOUND -1 // The HTTP response does not seem to carry an interesting file
#define FILE_WAIT_FOR_RESP_BODY 0 // Received HTTP reponse header, but need to wait to see at least the first few bytes of the response body
/////////////////////////


/////////////////////////
// Other useful constants...
#define KB_SIZE 1024
#define MAX_FILE_DUMP_SIZE 2*KB_SIZE*KB_SIZE
#define MAX_IP_LEN 15 // 3*4+3
#define MAX_KEY_LEN 60 // larger than really needed
#define MAX_URL_LEN 512
#define MAX_UA_LEN 256
#define MAX_HOST_LEN 256
#define MAX_REFERER_LEN 512
#define MAX_DUMPDIR_LEN 256
#define MAX_NIC_NAME_LEN 10 // larger than really needed
#define TMP_SUFFIX_LEN 4
#define MAX_PAYLOAD_LEN 1460
#define MAX_HTTP_HDR_LEN 3*KB_SIZE
#define MAX_SC_INIT_PAYLOADS 4
#define INIT_SC_PAYLOAD 6*KB_SIZE // 6KB are enough to hold 4 TCP segments of 1460 payload bytes each; this should be plenty to allow us to determine if an HTTP response is carrying a file download of interest
#define REALLOC_SC_PAYLOAD 128*KB_SIZE // 128KB increments are used when tracking a file download; notice that M_MMAP_THRESHOLD should be set to the same amount to allow for the blocks to be returned to the OS once the process frees them
#define TRIM_PAYLOAD_ALLOC 8*INIT_SC_PAYLOAD // used to set M_TRIM_THRESHOLD

#define TRUE 1
#define FALSE 0

#define NA_DIR 0 // flow direction not yet defined
#define CS_DIR 1 // Current flow direction is Client->Server
#define SC_DIR 2 // Curretn flow direction is Server->Client
#define LRUC_SIZE 10000 // Max number of TCP flows tracked for reconstruction at any given time

#define CORRUPT_MISSING_DATA 1
#define CORRUPT_MISSING_DATA_INVALID_SEQ_LIST  2
#define CORRUPT_MISSING_DATA_EST_LEN_TOO_SHORT 3
#define CORRUPT_MISSING_DATA_EST_LEN_TOO_LONG  4
#define CORRUPT_MISSING_DATA_TRIGGERED_KILL_SWITCH 5
#define CORRUPT_INVALID_RESPONSE_LEN 6
#define POSSIBLY_CORRUPT_FLOW_ID_COLLISION 7
#define POSSIBLY_CORRUPT_FLOW_UNEXPECTEDLY_DESTROYED 8
/////////////////////////


/////////////////////////
// Data structure used for TCP/HTTP flow reconstruction
struct tcp_flow {
        short flow_state;

        // Client srcIP -- used to track http request sequences
        char srcip[MAX_IP_LEN+1];

        // Client->Server half-flow
        char cs_key[MAX_KEY_LEN+1];
        char anon_cs_key[MAX_KEY_LEN+1]; // anonymized cs_key
        char url[MAX_URL_LEN+1];    // URL (including HTTP mothod and HTTP/1.x)
        char host[MAX_HOST_LEN+1];   // Host: header field
        char referer[MAX_REFERER_LEN+1];   // Host: header field

        // Server->Client half-flow
        char sc_key[MAX_KEY_LEN+1];
        u_int sc_init_seq;     // The sequence number of the first packet in the payload buffer 
        u_int sc_expected_seq; // The next expected sequence number 
        char* sc_payload;
        u_int sc_payload_size;     // Indicates the current number of bytes in the flow payload 
        u_int sc_payload_capacity; // Indicates the current capacity of the payload buffer 
        u_int sc_num_payloads; // number of packets sent with payload_size > 0
        seq_list_t *sc_seq_list;

        short corrupt_pe; // TRUE or FALSE; records whether the reconstructed file is believed to be corrupt

        short client_fin;  // tracks FIN sent by client
        short server_fin;  // tracks FIN sent by server
        short flow_closed; // indicates if the flow has been closed (by FIN or RST)

        /* Stores the number of the requests in the connection. Useful when there
           is more than one http request for executables in the same 
           connection. This is appended to the name of the dumped file */
        int http_request_count;
};
/////////////////////////


/////////////////////////
// Data structure used by file dump thread
#define DUMP_FILE_NAME_LEN 120
struct dump_payload_thread {
        char dump_file_name[DUMP_FILE_NAME_LEN+1];
        char url[MAX_URL_LEN+1];     // URL (including HTTP mothod and HTTP/1.x)
        char host[MAX_HOST_LEN+1];   // Host: header field
        char referer[MAX_REFERER_LEN+1];   // Referer: header field
        short corrupt_pe; // records if file is believed to be corrupt
        char *file_payload;
        u_int file_payload_size;
        seq_list_t *sc_seq_list;
};
/////////////////////////


/////////////////////////
// Data structures used to track sequences of HTTP queries
typedef struct http_req_value {
    struct timeval time;
    char servip[MAX_IP_LEN+1];
    char host[MAX_HOST_LEN+1];
    char refhost[MAX_HOST_LEN+1];
    char ua[MAX_UA_LEN+1]; // generalized user agent string
} http_req_value_t;

typedef struct http_req_value_dyn {
    char* url;
    char* ua; // generalized user agent string
} http_req_value_dyn_t;
/////////////////////////


pcap_t *pch = NULL;      /* packet capture handler */
struct bpf_program pcf;  /* compiled BPF filter */

struct pcap_stat stats;
struct pcap_stat *statsp;

int anonymize_srcip = TRUE; // used to anonymize client IP for all downloads and debug info
unsigned long xor_key = 0;

int max_dump_file_size;
char *dump_dir = NULL;
char *nic_name = NULL;
lru_cache_t *lruc = NULL;

////////////////////////////////
ghash_table_t* triggers_ht = NULL;
glru_cache_t* glruc_q = NULL;
pthread_mutex_t glruc_q_mutex;
////////////////////////////////

static void stop_pcap(int);
static void print_stats(int);
static void clean_and_print_lruc_stats(int);
void print_usage(char* cmd);
void packet_received(char *args, const struct pcap_pkthdr *header, const u_char *packet);
struct tcp_flow* init_flow(const char *srcip, const char *key, const char *rev_key, const char *anon_key);
struct tcp_flow* lookup_flow(lru_cache_t *lruc, const char *key);
void store_flow(lru_cache_t *lruc, const char *key, struct tcp_flow *tflow);
void remove_flow(lru_cache_t *lruc, struct tcp_flow *tflow);
void update_flow(struct tcp_flow *tflow, const struct tcp_header *tcp, const char *payload, const int payload_size);
void reset_flow_payload(struct tcp_flow *tflow);
void tflow_destroy(void *e);

char *boyermoore_search(const char *haystack, const char *needle);
void get_key(char *key, const char* pkt_src, const char *pkt_dst);
void itoa(int n, char *s);
void reverse(char *s);
int is_http_request(const char *payload, int payload_size);
int is_complete_http_resp_header(const struct tcp_flow *tflow);
int contains_interesting_file(const struct tcp_flow *tflow);
char* get_url(char* url, const char *payload, int payload_size);
char* get_host(char* host, const char *payload, int payload_size);
char* get_host_domain(char* host, const char *payload, int payload_size);
char* get_referer(char* referer, const char *payload, int payload_size);
char* get_ref_host(char* refhost, const char *payload, int payload_size);
char* get_user_agent(char* ua, const char *payload, int payload_size);
int get_content_length(const char *payload, int payload_size);
int get_resp_hdr_length(const char *payload, int payload_size);
int parse_content_length_str(const char *cl_str);
short is_missing_flow_data(seq_list_t *l, int flow_payload_len);
void dump_pe(struct tcp_flow *tflow);
void *dump_file_thread(void* d);

bool equal_httpreq(http_req_value_t* v1, http_req_value_t* v2);
bool str_starts_with(char* s1, char* s2);


///////////////////////////
// Used for tracking HTTP request sequences
#define FIFOQ_LEN 1000
#define GLRUC_TTL 3600 // 1h
#define GLRUC_LEN 100000
#define NOTIFY_FNAME_LEN 1024
#define HTTPREQLIST_PREFIX "httpreqlist-"
#define TS_STR_LEN 20

void fifoq_destroy_fn(void* q);
void print_http_req_value(void* v, FILE* f);
void print_http_req_list(fifo_queue_t* q, FILE* f, time_t time_limit);
ghash_table_t* init_httpreq_triggers_ht(char* triggers_fname);
///////////////////////////


///////////////////////////
// Debug levels 
// #define FILE_DUMP_DEBUG 1 // Debug messages will work only if FILE_DUMP_DEBUG is defined
#define QUIET 1
#define VERBOSE 2
#define VERY_VERBOSE 3
#define VERY_VERY_VERBOSE 4
int debug_level = QUIET;
///////////////////////////

///////////////////////////
// Network traffic stats
u_int stats_num_half_open_tcp_flows = 0;
u_int stats_num_new_tcp_flows = 0;
u_int stats_num_new_http_flows = 0;
u_int stats_num_new_file_flows = 0;
///////////////////////////


///////////////////////////
// File types that may be dumped
bool find_pe_files  = true; // on by default!
bool find_elf_files = false;
bool find_dmg_files = false;
bool find_zip_files = false;
bool find_jar_files = false;
bool find_rar_files = false;
bool find_pdf_files = false;
bool find_swf_files = false;
bool find_msdoc_files = false;
///////////////////////////


///////////////////////////
// HTTP request list tracking and logging
char* httpreq_track_dir = NULL;
char* httpreq_triggers_file = NULL;
bool track_httpreq_sequences = false;
bool dump_httpreq_list_thread_must_exit = false;
char* dump_notify_dir = NULL;

void create_dev_shm_tmp_file(char* fname);
void remove_dev_shm_tmp_file(char* fname);
void* dump_httpreq_list_thread(void* notify_dir);
void* notify_httpreq_match_thread(void* fname);
void interrupt_dump_httpreq_list_thread();
char* get_srcip_from_httpreq_fname(char* fname);
time_t get_time_from_httpreq_fname(char* fname);
///////////////////////////



///////////////////////////
int main(int argc, char **argv) {

    char *pcap_filter;
    char *pcap_file;
    // bpf_u_int32 net;
    char err_str[PCAP_ERRBUF_SIZE];

    int lruc_size = LRUC_SIZE;

    pcap_handler callback = (pcap_handler)packet_received;


    if(argc < 3) {
        print_usage(argv[0]);
        exit(1);
    }


    max_dump_file_size = MAX_FILE_DUMP_SIZE;
    dump_dir = NULL;
    pcap_filter = NULL;
    nic_name = NULL;
    pcap_file = NULL;

    int op;
    while ((op = getopt(argc, argv, "hi:r:d:f:D:L:K:H:T:AWMGZPERSJ")) != -1) {
        switch (op) {

        case 'h': // shows command usage/help
            print_usage(argv[0]);
            exit(1);
            break;
 
        case 'A': // is set, this flag turns off the default on-the-fly srcIP anonymization
            anonymize_srcip = FALSE;
            break;

        case 'i': // NIC to listen from
            nic_name = strdup(optarg);
            break;

        case 'r': // Read packets from .pcap file instead of NIC
            pcap_file = optarg;
            break;

        case 'd': // Dump directory where raw HTTP responses containing PF files are dropped
            dump_dir = optarg;
            break;

        case 'f': // Used to express BPF filter
            pcap_filter = optarg;
            break;

        case 'D': // Defines level of debug messages (only useful if FILE_DUMP_DEBUG is defined)
            if(atoi(optarg) >= QUIET)
                debug_level = atoi(optarg);
            break;

        case 'L': // Specify size of LRU cache (max number of entries)
            if(atoi(optarg) > 0)
                lruc_size = atoi(optarg);
            break;

        case 'K': // Max acceptable size of reconstructed files
            if(atoi(optarg) > 0)
                max_dump_file_size = atoi(optarg) * KB_SIZE; // size in KB
            break;

        case 'W': // turn off dump of Windows PE files
            find_pe_files = FALSE;
            break;

        case 'Z': // turn on dump of ZIP files (includes JAR, APK, DOCX, PPTX, XLSX, XAP, etc.)
            find_zip_files = TRUE;
            break;

        case 'J': // turn on dump of JAR and APK files
            find_jar_files = TRUE;
            break;

        case 'E': // turn on dump of ELF files
            find_elf_files = TRUE;
            break;

        case 'P': // turn on dump of PDF files
            find_pdf_files = TRUE;
            break;

        case 'M': // turn on dump of MS Office docs (DOC, PPT, XLS, etc.)
            find_msdoc_files = TRUE;
            break;

        case 'G': // turn on dump of Mac OS DMG files
            find_dmg_files = TRUE;
            break;

        case 'R': // turn on dump of RAR files
            find_rar_files = TRUE;
            break;

        case 'S': // turn on dump of SWF files
            find_swf_files = TRUE;
            break;

        case 'H': // turn on HTTP request list tracking
            httpreq_track_dir = optarg;
            track_httpreq_sequences = true;
            dump_notify_dir = "/dev/shm"; // FIXME(Roberto): make it configurable
            break;

        case 'T': // HTTP request list tracking triggers (list of domains)
            httpreq_triggers_file = optarg; // file should contain a list of host names
            track_httpreq_sequences = true;
            break;

        }
    }


    // initialize anonymization key
    if(anonymize_srcip)
        xor_key = (unsigned long)time(NULL);

    printf("Starting %s...\n", argv[0]);
    printf("MAX DUMP FILE SIZE = %d KB\n", max_dump_file_size/KB_SIZE);
    printf("LRU CACHE SIZE = %d\n",lruc_size);


    // Set signal handlers
    signal(SIGTERM, stop_pcap);
    signal(SIGINT,  stop_pcap);
    signal(SIGUSR1, print_stats);
    signal(SIGUSR2, clean_and_print_lruc_stats);


    // Make sure we know where to store the reconstructed files
    if(dump_dir == NULL) {
        fprintf(stderr, "dump_dir must to be specified\n");
        print_usage(argv[0]);
        exit(1);
    }

    if(dump_dir != NULL) {
        struct stat stat_buf;
        if(stat(dump_dir, &stat_buf) != 0) {
            fprintf(stderr, "dump_dir %s not found\n", dump_dir);
            print_usage(argv[0]);
            exit(1);
        }
        printf("DUMP DIR = %s\n", dump_dir);
    }



    // Initialize LRU cache used to track/reassemble TCP flows        
    lruc = lruc_init(lruc_size, tflow_destroy);

    // Initialize GLRU cache used to track sequences of requests        
    glruc_q = glruc_init(GLRUC_LEN, GLRUC_TTL, true, false, true, true, 0, NULL, fifoq_destroy_fn);


    if(track_httpreq_sequences) {
        if(httpreq_track_dir == NULL) {
            fprintf(stderr, "httpreq_track_dir must to be specified\n");
            print_usage(argv[0]);
            exit(1);
        }

        if(httpreq_triggers_file != NULL) {
            triggers_ht = init_httpreq_triggers_ht(httpreq_triggers_file);
        }

        pthread_t thread_id;
        pthread_create(&thread_id,NULL,dump_httpreq_list_thread,(void*)dump_notify_dir);
        pthread_detach(thread_id); // this allows for the thread data structures to be reclaimed as soon as thread ends
    }


    // Start reading from device or file
    *err_str = '\0';
    if(pcap_file!=NULL) {
        pch = pcap_open_offline(pcap_file,err_str);
        if(pch == NULL) {
            fprintf(stderr, "Couldn't open the file %s: %s\n",pcap_file,err_str);
            exit(1);
        }
        printf("Reading from %s\n", pcap_file);
    }
    else if(nic_name!=NULL) {
        pch = pcap_open_live(nic_name, PCAP_SNAPLEN, 1, 1000, err_str);
        if (pch == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s", nic_name, err_str);
            exit(1);
        }
        printf("Listening on %s\n", nic_name);
    }

    /* make sure we are capturing from an Ethernet device */
    if(pcap_datalink(pch) != DLT_EN10MB) {
        fprintf(stderr, "Device is not an Ethernet\n");
        exit(EXIT_FAILURE);
    }

    /* BPF filter */
    if(pcap_filter == NULL)
        pcap_filter = NULL;
        // pcap_filter = "tcp"; // default filter
    if(pcap_compile(pch, &pcf, pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",pcap_filter, pcap_geterr(pch));
        exit(1);
    }

    /* apply BPF filter */
    if (pcap_setfilter(pch, &pcf) == -1) {
        fprintf(stderr, "Couldn't set filter %s: %s\n",pcap_filter, pcap_geterr(pch));
        exit(1);
    }

    printf("BPF FILTER = %s\n", pcap_filter);



    // We need to adjust the memory allocation behavior before we start capturing packets
    // With this we are trying to make sure that memory blocks used to reconstruct file downloads can be reclaimed by the OS
    if(!mallopt(M_MMAP_THRESHOLD, REALLOC_SC_PAYLOAD)) {
        fprintf(stderr, "mallopt could not set M_MMAP_THRESHOLD to %d!\n", REALLOC_SC_PAYLOAD);
        exit(1);
    }

    // We decrease the M_TRIM_THRESHOLD to have a higher chance of releasing freed memory blocks to the OS
    // This may decrease performance to some extent, in that it tends to increase the number of system calls
    // so, TRIM_PAYLOAD_ALLOC should not be too much lower than the default value (see mallopt() docs)
    if(!mallopt(M_TRIM_THRESHOLD, TRIM_PAYLOAD_ALLOC)) {
        fprintf(stderr, "mallopt could not set M_TRIM_THRESHOLD to %d!\n", TRIM_PAYLOAD_ALLOC);
        exit(1);
    }


    /* start listening */
    printf("Reading packets...\n\n");
    fflush(stdout);

    pcap_loop(pch, MAX_RCV_PACKETS, callback, NULL);

    printf("Done reading packets!\n\n");

    interrupt_dump_httpreq_list_thread();

    pthread_exit(NULL); // exit but allows other threads to termiate gracefully
}

void print_usage(char* cmd) {

    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: %s [-i NIC] [-r pcap_file] [-A] -d dump_dir [-f \"pcap_filter\"] [-L lru_cache_size] [-K max_dump_file_size (KB)] [-D debug_level] \n",cmd);
    fprintf(stderr, "\n");


    fprintf(stderr, "\t -i : Use to specify network interface (e.g., -i eth0)\n");
    fprintf(stderr, "\t -r : Read from .pcap file instead of NIC (e.g., -r file.pcap)\n");  
    fprintf(stderr, "\t -A : If specified, this flag will turn off the on-the-fly srcIP anonymization\n");
    fprintf(stderr, "\t -d : Director where raw HTTP respnoses containing reconstructed files are stored (e.g., -d ./dumps\n");
    fprintf(stderr, "\t -f : Specify BPF filter (e.g., -f \"tcp port 80\")\n");
    fprintf(stderr, "\t -L : Change LRU cache size (default = 10000 entries)\n");
    fprintf(stderr, "\t -K : Change max accepted reconstructed file size, in KB (e.g., -K 1024)\n");
    fprintf(stderr, "\t -D : Specify debug_level (value from 0-4)\n");

    // WMGZPERSJ
    fprintf(stderr, "\t -J : extract JAR/APK files\n");
    fprintf(stderr, "\t -E : extract ELF files\n");
    fprintf(stderr, "\t -G : extract DMG files\n");
    fprintf(stderr, "\t -Z : extract ZIP files\n");
    fprintf(stderr, "\t -R : extract RAR files\n");
    fprintf(stderr, "\t -P : extract PDF files\n");
    fprintf(stderr, "\t -M : extract MS DOC files\n");
    fprintf(stderr, "\n");
}



void packet_received(char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    //////////////////////////////
    if(header->len > PCAP_SNAPLEN) { // skip truncated packets

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
	        printf("LEN > PCAP_SNAPLEN !!!");
            printf("header->len = %u\n", header->len);
            printf("PCAP_SNAPLEN = %u\n", PCAP_SNAPLEN);
            fflush(stdout);
        }
        #endif

        return;
    }
    //////////////////////////////


    //////////////////////////////
    // Check what packet type this ethernet frame is carrying
    #define ETH_TYPE_IP 0x0800
    #define VLAN8021Q_HDR_TYPE 0x8100
    struct eth_header *ep;
    u_short eth_hdr_len = ETH_HEADER_LEN;
    u_short eth_type = 0;

    ep = (struct eth_header *)packet;
    eth_type = ntohs(ep->eth_type);
    // printf("Ethernet type = %x\n", eth_type);
    if(eth_type == VLAN8021Q_HDR_TYPE) { // this is a VLAN tagged frame!
        eth_hdr_len += ETH_VLAN_HDR_LEN; // 802.1Q Header len = 4 byes

        struct eth_vlan_header *epvlan = (struct eth_vlan_header *)packet;
        eth_type = ntohs(epvlan->eth_type); // retrieve the actual ethernet type
    }

    if(eth_type != ETH_TYPE_IP) // this is not an IP packet!
        return;

    // we count if this is a valid IP packet
    static u_int pkt_count = 0;
    pkt_count++;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Packet %d\n", pkt_count);
        fflush(stdout);
    }
    #endif
    //////////////////////////////


    //////////////////////////////
    // Parse IP packets
    const struct ip_header  *ip;
    const struct tcp_header *tcp;
    const char* payload;
    struct tcp_flow *tflow;

    u_int ip_hdr_size;
    u_int tcp_hdr_size;
    int payload_size;

    ip  = (const struct ip_header*)(packet + eth_hdr_len);
    ip_hdr_size = IP_HEADER_LEN(ip)*4;
    tcp = (const struct tcp_header*)(packet + eth_hdr_len + ip_hdr_size); 
    tcp_hdr_size = TH_OFF(tcp)*4;
    payload = (const char*)(packet + eth_hdr_len + ip_hdr_size + tcp_hdr_size);
    payload_size = ntohs(ip->ip_len) - (ip_hdr_size + tcp_hdr_size);

    // we skip invalid packets whose headers are too small
    #define MIN_IP_TCP_HDR_LEN 20
    if(ip_hdr_size < MIN_IP_TCP_HDR_LEN || tcp_hdr_size < MIN_IP_TCP_HDR_LEN) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Invalid packet (headers are too small)\n");
            printf("ip_hdr_size = %d ; tcp_hdr_size = %d \n", ip_hdr_size, tcp_hdr_size);
            fflush(stdout);
        }
        #endif
        return;
    }

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("ip_len = %u\n", ntohs(ip->ip_len));
        printf("ip_hdr_size = %u\n", ip_hdr_size);
        printf("tcp_hdr_size = %u\n", tcp_hdr_size);
        printf("payload_size = %u\n", payload_size);
        // printf("%s", payload);
        fflush(stdout);
    }
    #endif
    //////////////////////////////


    //////////////////////////////
    // Skip ACK-only packets or other empty packets
    if(payload_size == 0 && !((tcp->th_flags & TH_SYN) || (tcp->th_flags & TH_FIN) || (tcp->th_flags & TH_RST))) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("skeeping empty packet \n");
            fflush(stdout);
        }
        #endif
        return;
    }
    //////////////////////////////


    //////////////////////////////
    // We now compute the packet IDs (srcIP, scrPort, dstIP, dstPort)
    #define PACKET_SRC_DST_ID_LEN 21 // String Format: IP:TCP_PORT -> xxx.xxx.xxx.xxx:xxxxx
    char srcip[MAX_IP_LEN+1];
    char dstip[MAX_IP_LEN+1];
    char pkt_src[PACKET_SRC_DST_ID_LEN+1];
    char pkt_dst[PACKET_SRC_DST_ID_LEN+1];
    char anon_pkt_src[PACKET_SRC_DST_ID_LEN+1]; // this is useufl for srcIPs that need to be anonymized on-the-fly

    char key[MAX_KEY_LEN+1];
    char anon_key[MAX_KEY_LEN+1];
    char rev_key[MAX_KEY_LEN+1];

    sprintf(pkt_src,"%s:%d",inet_ntoa(ip->ip_src),ntohs(tcp->th_sport));
    sprintf(pkt_dst,"%s:%d",inet_ntoa(ip->ip_dst),ntohs(tcp->th_dport));
    get_key(key,pkt_src,pkt_dst);
    get_key(rev_key,pkt_dst,pkt_src);


    // Compute anonymized source IP and flow key
    struct in_addr anon_ip_src = ip->ip_src;

    anon_key[0] = '\0'; // empty
    if(anonymize_srcip) {
        anon_ip_src.s_addr = ((anon_ip_src.s_addr ^ xor_key) & 0xFFFFFF00) | 0x0000000A; // --> 10.x.x.x
        sprintf(anon_pkt_src,"%s:%d",inet_ntoa(anon_ip_src),ntohs(tcp->th_sport));
        get_key(anon_key,anon_pkt_src,pkt_dst);
    }

    sprintf(srcip,"%s",inet_ntoa(anon_ip_src));
    sprintf(dstip,"%s",inet_ntoa(ip->ip_dst));
    //////////////////////////////


    //////////////////////////////
    // Check if this is a new flow
    if(tcp->th_flags == TH_SYN) {
        
        tflow = init_flow(srcip, key, rev_key, anon_key); // initialize data structures
        if(tflow == NULL)
            return;

        // in the rare (but possible) case of 4-tuple collisions, we remove the previous flow from cache 
        struct tcp_flow *tmp_tflow; 
        if((tmp_tflow = lookup_flow(lruc, tflow->cs_key)) != NULL) {
            if(tmp_tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND) {
                // record premature end of flow. File most likely corrupt
                tmp_tflow->corrupt_pe = POSSIBLY_CORRUPT_FLOW_ID_COLLISION;

                // dump reconstructed File file
                dump_pe(tmp_tflow);
            }
            remove_flow(lruc, tmp_tflow);
        }
        
        // store TCP flow into LRU cache; 
        // notice that the lookup key is the 4-tuple for the Client->Server direction
        store_flow(lruc, tflow->cs_key, tflow); 

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERBOSE) {
            printf("Found a new TCP flow: %s\n",tflow->anon_cs_key);
            fflush(stdout);
        }
        #endif

        stats_num_half_open_tcp_flows++;
        return;
    } // if this is not a new flow, we keep going...
    //////////////////////////////
    


    //////////////////////////////
    // OK, so now we need to see if we have been tracking this TCP flow
    short flow_direction = NA_DIR; // flow direction is currently undefined; we need to find out...

    // We assume this packet is on the Server->Client direction first, 
    // since there are usually many more SC packets than CS packets.
    // The flow "reverse key" below is essentially the client-to-server 4-tuple identifier
    get_key(rev_key,pkt_dst,pkt_src); // this computes the key for LRU cache lookup

    if((tflow = lookup_flow(lruc, rev_key)) != NULL) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("TCP flow %s, server-to-client direction\n", tflow->anon_cs_key);
            fflush(stdout);
        }
        #endif

        flow_direction = SC_DIR; // if there is an entry, we can confirm this is a Server->Client packet
    }
    else { // if there is no entry, then we check if this is a Client->Server packet
        get_key(rev_key,pkt_src,pkt_dst); 

        if((tflow = lookup_flow(lruc, key)) != NULL) {
            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("TCP flow %s, client-to-server direction\n", tflow->anon_cs_key);
                fflush(stdout);
            }
            #endif

            flow_direction = CS_DIR; // if there is an entry, we can confirm this is a Client->Server packet
        }
        else
            return; // we don't have a TCP flow in cache for this packet...
    }
    //////////////////////////////
    


    //////////////////////////////
    // check if it appears the flow is being closed
    if((tcp->th_flags & TH_RST) || (tcp->th_flags & TH_FIN)) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERBOSE) {
            printf("TCP flow %s is being closed\n", tflow->anon_cs_key);
            fflush(stdout);
        }
        #endif

        if(tcp->th_flags & TH_RST) {
            tflow->flow_state = FLOW_FILE_RESET;
            tflow->flow_closed = TRUE; // the flow is reset, abandon it!
	}

        if(flow_direction == SC_DIR) {
            // printf("SC-FIN\n");
            tflow->server_fin = TRUE;

            if(tcp->th_flags & TH_FIN) {
                if(payload_size > 0) {
                    // the FIN packet may contain data; therefore, we need to update the flow's payload
                    update_flow(tflow, tcp, payload, payload_size);
                    // record what was the last file byte in the S->C half flow (from the SEQ number in server's FIN packet)
                    seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_seq), payload_size); 
                }
            }
        }


        if(flow_direction == CS_DIR) {
            // printf("CS-FIN\n");
            tflow->client_fin = TRUE;

            // TODO(Roberto): double-check whether the behavior coded below is correct
            // what if the server sends more data, before its own FIN?
            if(tcp->th_flags & TH_FIN) { 
                // we assume the server is not going to send more data after client sends a FIN packet
                // record what was the last expected file byte from the server (from the ACK number in client's FIN packet)
                seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_ack)-1, 0); // the -1 is due to how seq# are defined at FIN-ACK
            }
        }


        if(tflow->client_fin && tflow->server_fin)
            tflow->flow_closed = TRUE; // the flow is closed!
        

        if(tflow->flow_closed) { //////////// FLOW IS CLOSED! ////////////////

          // if this flow contains an interesting file, dump it
          if(tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND) {

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERBOSE) {
                printf("TCP flags = %x\n", tcp->th_flags);
                if(tcp->th_flags & TH_FIN) printf("FIN\n");
                if(tcp->th_flags & TH_RST) printf("RST\n");
                printf("File flow %s is being closed and dumped: payload size = %d\n", tflow->anon_cs_key, tflow->sc_payload_size);
                printf("Flow Direction = %d\n", flow_direction);
                fflush(stdout);
            }
            #endif


            dump_pe(tflow); // dump the reconstructed file

          }

          remove_flow(lruc, tflow); // evict closed TCP flow from cache

        } //////////// END FLOW IS CLOSED! ////////////////

        return;
    }
    //////////////////////////////



    //////////////////////////////
    if(flow_direction == CS_DIR) {
    // Clinet to Server packet. Check and update HTTP query state


        // if first request packet
        if(tflow->flow_state == FLOW_SYNACK) {
            if(!is_http_request(payload, payload_size)) { // we are only interested in valid HTTP traffic
                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERBOSE) {
                    printf("Non-HTTP TCP flow is being removed from the cache\n");
                    fflush(stdout);
                }       
                #endif

                remove_flow(lruc, tflow);
                return;
            }

            tflow->flow_state = FLOW_HTTP;
            stats_num_new_http_flows++;
        }

        if(tflow->flow_state == FLOW_HTTP && !is_http_request(payload, payload_size)) {
            // something strage happend... we'll wait for next valid HTTP request
            return;
        }
        
        if(tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND) { 
            // we were reconstructing a (possible) file, and now there is another client HTTP request...
            
            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERBOSE) {
                printf("File flow %s is being closed and dumped (new HTTP req): payload size = %d\n", tflow->anon_cs_key, tflow->sc_payload_size);
                fflush(stdout);
            }
            #endif

            // record the last byte expected from the server (from client's ack)
            seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_ack), 0);

            // dump reconstructed file
            dump_pe(tflow);

            // wait for a new HTTP request
            tflow->flow_state = FLOW_HTTP;
        }
    
        // We only consider the very first packet of each HTTP req to extract URL and Host
        // Currently we cannot deal with packet reordering for HTTP req in multiple packets
        if(is_http_request(payload, payload_size) && tflow->flow_state != FLOW_HTTP_RESP_HEADER_WAIT) { 
            // We need to record URL, Host, etc., so that we can report them if a file occurs

            tflow->flow_state = FLOW_HTTP_RESP_HEADER_WAIT;
            tflow->http_request_count++;

            get_url(tflow->url, payload, payload_size);
            get_host(tflow->host, payload, payload_size);
            get_referer(tflow->referer, payload, payload_size);

            fifo_queue_t* q;
            http_req_value_t httpreq;
            gettimeofday(&httpreq.time, NULL);
            httpreq.servip[0]='\0';
            httpreq.host[0]='\0';
            httpreq.refhost[0]='\0';
            httpreq.ua[0]='\0';

            strncpy(httpreq.servip,dstip,MAX_IP_LEN);
            httpreq.servip[MAX_IP_LEN]='\0';
            get_host_domain(httpreq.host, payload, payload_size);
            get_ref_host(httpreq.refhost, payload, payload_size);
            get_user_agent(httpreq.ua, payload, payload_size);
            
            pthread_mutex_lock(&glruc_q_mutex);
            glruc_entry_t* e = glruc_search(glruc_q, tflow->srcip);
            pthread_mutex_unlock(&glruc_q_mutex);

            if(e == NULL) {
                q = fifoq_init(FIFOQ_LEN, true, true, sizeof(http_req_value_t), NULL, NULL);
                pthread_mutex_lock(&glruc_q_mutex);
                glruc_insert(glruc_q, srcip, q);
                pthread_mutex_unlock(&glruc_q_mutex);
            }
            else {
                q = (fifo_queue_t*)e->value;
            }
            if(!equal_httpreq(&httpreq,fifoq_get_last_value(q))) {
                fifoq_insert(q, &httpreq);
            }

            if(ght_search(triggers_ht,httpreq.host)!=NULL) {
                // store httpreq queue

                ////////////////////////////////////
                // Notify all listening processes that http request list 
                // for srcip must be dumpted
                char* notify_fname = (char*)malloc(sizeof(char)*(NOTIFY_FNAME_LEN+1));
                char ts_str[TS_STR_LEN+1];
                itoa(httpreq.time.tv_sec,ts_str);

                notify_fname[0]='\0';
                strcat(notify_fname,HTTPREQLIST_PREFIX);
                strcat(notify_fname,"domain");
                strcat(notify_fname,"_");
                strcat(notify_fname,ts_str);
                strcat(notify_fname,"_");
                strncat(notify_fname,tflow->cs_key,MAX_KEY_LEN+1);

                pthread_t th_id;
                pthread_create(&th_id,NULL,notify_httpreq_match_thread,(void*)notify_fname);
                pthread_detach(th_id); 
                ////////////////////////////////////
            }

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERBOSE) {
                printf("Found HTTP request: %s : %s : %s\n",
                    tflow->host, 
                    tflow->url,
                    tflow->referer);
                printf("Flow state = %d\n", tflow->flow_state);
                fflush(stdout);
            }
            #endif
        } 

    }
    //////////////////////////////


    //////////////////////////////
    else if(flow_direction == SC_DIR) {
    // Server->Client packet. Check and update HTTP response state

        if((tcp->th_flags & TH_SYN) && (tcp->th_flags & TH_ACK)) {
            // SYN-ACK packet

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Found a SYNACK for TCP flow: %s\n",tflow->anon_cs_key);
                fflush(stdout);
            }
            #endif

            stats_num_new_tcp_flows++;

            tflow->flow_state = FLOW_SYNACK;
            return;
        }


        if(tflow->flow_state == FLOW_HTTP) {
            // we are still waiting for a proper HTTP request
            // don't consider resp packets until that happens
            return;
        }

        if(tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND && tflow->sc_payload_size > max_dump_file_size) {
            // This file is too large, skip it! (we are not going to dump it)
            tflow->flow_state = FLOW_HTTP;
            reset_flow_payload(tflow);
            return;
        }

        // This seems a valid response packet, and we should therefore
        // update tcp seq numbers and payload content
        update_flow(tflow, tcp, payload, payload_size);
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Flow %s has been updated \n",tflow->anon_cs_key);
            fflush(stdout);
        }
        #endif

        if(tflow->flow_state == FLOW_HTTP_RESP_HEADER_WAIT) {
            // OK, we were waiting for a complete HTTP response header
            // so, we should check if we got it with this packet

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Flow state is FLOW_HTTP_RESP_HEADER_WAIT \n");
                fflush(stdout);
            }
            #endif

            // check if we got a complete HTTP response header...
            if(is_complete_http_resp_header(tflow)) {
                // if so, we can start waiting to see if the response will carry a file 
                tflow->flow_state = FLOW_HTTP_RESP_MAGIC_WAIT;

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("HTTP resp header is complete \n");
                    printf("Flow state is FLOW_HTTP_RESP_MAGIC_WAIT \n");
                    fflush(stdout);
                }
                #endif
            }
            else if(tflow->sc_num_payloads > MAX_SC_INIT_PAYLOADS) {
                // if we received many Server->Client packets, but the HTTP response
                // is still not complete, we should reset this flow

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("tflow->sc_num_payloads > MAX_SC_INIT_PAYLOADS \n");
                    fflush(stdout);
                }
                #endif

                tflow->flow_state = FLOW_HTTP; // return to wait for new HTTP request
                reset_flow_payload(tflow);

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Flow state reset to FLOW_HTTP \n");
                    fflush(stdout);
                }
                #endif

                return; // wait for next packet
            }
        }

        // We have received a complete HTTP response header
        // so now we should check for a possible file carried in the reponse body
        if(tflow->flow_state == FLOW_HTTP_RESP_MAGIC_WAIT) {

            int resp = FILE_NOT_FOUND; // still waiting to see if we find a possible file of interest
            int contentlen = get_content_length(tflow->sc_payload, tflow->sc_payload_size); // extract content lenght from HTTP response header

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Flow state is FLOW_HTTP_RESP_MAGIC_WAIT \n");
                printf("contentlen = %d", contentlen);
                fflush(stdout);
            }
            #endif


            // We first make sure the content length is less than max_dump_file_size
            // otherwise we don't even try to check if there is a large file... force to abandon this flow!
            if (contentlen > 0 && contentlen < max_dump_file_size) {
                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Calling contains_interesting_file... \n");
                    fflush(stdout);
                }
                #endif
                resp = contains_interesting_file(tflow);
            }

            if(resp == FILE_FOUND) { // Found indication of a possible file of interest in the reponse
                tflow->flow_state = FLOW_HTTP_RESP_MAGIC_FOUND;
                stats_num_new_file_flows++;
                // #ifdef FILE_DUMP_DEBUG
                // if(debug_level >= QUIET) {
                    printf("Found file flow : %s\n", tflow->anon_cs_key);
                    fflush(stdout);
                // }
                // #endif
            }
            else if(resp == FILE_WAIT_FOR_RESP_BODY) { // Need to wait to see at least first few bytes of the reponse body
                if(tflow->sc_num_payloads > MAX_SC_INIT_PAYLOADS) { 
                    // if we have already got more than MAX_SC_INIT_PAYLOADS we give up on this reponse

                    #ifdef FILE_DUMP_DEBUG
                    if(debug_level >= VERY_VERY_VERBOSE) {
                        printf("tflow->sc_num_payloads > MAX_SC_INIT_PAYLOADS \n");
                        fflush(stdout);
                    }
                    #endif
                    
                    // we are not going to wait any longer
                    tflow->flow_state = FLOW_HTTP; // go back to waiting for a new HTTP request
                    reset_flow_payload(tflow); 
                }
            }
            else if(resp == FILE_NOT_FOUND) {
                // The response is likely not carrying what we are interested in
                tflow->flow_state = FLOW_HTTP; // return to wait for new HTTP request
                reset_flow_payload(tflow);
            }
        }
    }
    //////////////////////////////

}


// Called at new TCP SYN
struct tcp_flow* init_flow(const char* srcip, const char *key, const char *rev_key, const char *anon_key) {

    struct tcp_flow *tflow = (struct tcp_flow*)malloc(sizeof(struct tcp_flow));
    if(tflow == NULL)
        return NULL;

    tflow->flow_state = FLOW_INIT;
    
    strcpy(tflow->srcip, srcip);

    strcpy(tflow->cs_key, key);
    if(strlen(anon_key)>0)
        strcpy(tflow->anon_cs_key, anon_key);
    else
        strcpy(tflow->anon_cs_key, key);
    strcpy(tflow->sc_key, rev_key);

    tflow->url[0] = '\0';
    tflow->host[0] = '\0';
    tflow->sc_payload = NULL;    

    tflow->sc_init_seq = 0;
    tflow->sc_expected_seq = 0;
    tflow->sc_payload_size = 0;
    tflow->sc_payload_capacity = 0;
    tflow->sc_num_payloads = 0;
    tflow->sc_seq_list = NULL;

    tflow->server_fin = FALSE;
    tflow->client_fin = FALSE;
    tflow->flow_closed = FALSE;

    tflow->corrupt_pe = FALSE;
    tflow->http_request_count = 0;

    return tflow;
}


struct tcp_flow* lookup_flow(lru_cache_t *lruc, const char *key) {
    return (struct tcp_flow*) lruc_search(lruc, key);
}


void store_flow(lru_cache_t *lruc, const char *key, struct tcp_flow *tflow) {
    lruc_insert(lruc, tflow->cs_key, tflow);
} 


void remove_flow(lru_cache_t *lruc, struct tcp_flow *tflow) {
    lruc_delete(lruc, tflow->cs_key);
}


void tflow_destroy(void *v) {

    struct tcp_flow *tflow = (struct tcp_flow *)v;

    if(tflow == NULL)
        return;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Destroying LRUC entry for %s\n", tflow->anon_cs_key);
        fflush(stdout);
    }
    #endif

    if(tflow->sc_payload != NULL && tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND) {
        // record the fact that flow is being unexpectedly terminated, file most likely corrupt
        tflow->corrupt_pe = POSSIBLY_CORRUPT_FLOW_UNEXPECTEDLY_DESTROYED;

        // dump reconstructed file
        dump_pe(tflow);
    }

    if(tflow->sc_payload!= NULL) { // we need to check again, because dump_pe might have changed things...
        free(tflow->sc_payload);
        tflow->sc_payload = NULL;

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Destroyed tflow->sc_payload\n");
            fflush(stdout);
        }
        #endif
    }

    if(tflow->sc_seq_list != NULL) {
        int mz_true = (tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND);
        seq_list_destroy(tflow->sc_seq_list, mz_true);
        tflow->sc_seq_list = NULL;

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Destroyed tflow->sc_seq_list\n");
            fflush(stdout);
        }
        #endif
    }
    
    free(tflow);

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Destroyed LRUC entry \n");
        fflush(stdout);
    }
    #endif
}


static void stop_pcap(int signo) {

    // properly destroy LRU cache fist 
    lruc_destroy(lruc);
    lruc = NULL;

    pthread_mutex_lock(&glruc_q_mutex);
    glruc_destroy(glruc_q);
    glruc_q = NULL;
    pthread_mutex_unlock(&glruc_q_mutex);

    ght_destroy(triggers_ht);

    fprintf(stderr, "\nCaught Signal #%d\n", signo);
    print_stats(signo);
    clean_and_print_lruc_stats(signo);

    interrupt_dump_httpreq_list_thread();

    pthread_exit(NULL);

}


static void clean_and_print_lruc_stats(int signo) {

    fprintf(stderr, "----------------------------------\n");
    if(lruc!=NULL) {
        fprintf(stderr, "LRU cache size (before celaning) = %d \n", lruc->num_entries);
        clean_lruc(lruc);
        fprintf(stderr, "LRU cache size (after cleaning) = %d \n", lruc->num_entries);
    }
    else {
        fprintf(stderr, "No LRU cache!\n");
    }
    fprintf(stderr, "----------------------------------\n");

}    


static void print_stats(int signo) {
    struct pcap_stat stat;

    fprintf(stderr, "----------------------------------\n");
    if (pcap_stats(pch, &stat) < 0) {
        fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pch));
        return;
    }
    // fprintf(stderr, "%u packets captured \n", packets_captured);
    fprintf(stderr, "%u packets received by filter \n", stat.ps_recv);
    fprintf(stderr, "%u packets dropped by kernel\n", stat.ps_drop);
    fprintf(stderr, "%u number of new half-open (SYN) tcp flows\n", stats_num_half_open_tcp_flows);
    fprintf(stderr, "%u number of new (SYN ACK) tcp flows\n", stats_num_new_tcp_flows);
    fprintf(stderr, "%u number of new http flows\n", stats_num_new_http_flows);
    fprintf(stderr, "%u number of new file flows\n", stats_num_new_file_flows);

    fprintf(stderr, "----------------------------------\n");
}


// we are only interested in GET, POST, and HEAD requests
int is_http_request(const char *payload, int payload_size) {

    if(payload_size < 5)
        return 0;

    if(strncmp("GET ", payload, 4) == 0)
        return 1;

    if(strncmp("POST ", payload, 5) == 0)
        return 1;

    if(strncmp("HEAD ", payload, 5) == 0)
        return 1;

    return 0;

}


char* get_url(char* url, const char *payload, int payload_size) {

    int i;

    for(i=0; i<MAX_URL_LEN && i<payload_size; i++) {
        if(payload[i] == '\r' || payload[i] == '\n') {
            // the first condition should suffice, but we check both just for sure...
            break;
        }

        url[i]=payload[i];
    }
    url[i]='\0'; // make sure it's properly terminated

    // printf("URL: %s\n",url);
    // fflush(stdout);
    
    return url;
}


char *get_host(char* host, const char *payload, int payload_size) {

    char haystack[payload_size+1];
    const char needle[] = "\r\nHost:";
    char *p = NULL;
    int i;

    strncpy(haystack, payload, payload_size);
    haystack[payload_size]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return "\0";

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        host[0] = '\0';
    else {
        p += 2; // skip \r\n
        for(i=0; i<MAX_HOST_LEN && (p+i) < &(haystack[payload_size]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            host[i]=*(p+i);
        }
        host[i]='\0';
    }

    return host;
}

char *get_host_domain(char* host, const char *payload, int payload_size) {

    char haystack[payload_size+1];
    const char needle[] = "\r\nHost: ";
    char *p = NULL;
    int i;

    strncpy(haystack, payload, payload_size);
    haystack[payload_size]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return "\0";

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        host[0] = '\0';
    else {
        p += strlen(needle); // skip \r\nHost:
        for(i=0; i<MAX_HOST_LEN && (p+i) < &(haystack[payload_size]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            host[i]=*(p+i);
        }
        host[i]='\0';
    }

    return host;
}


char *get_referer(char* referer, const char *payload, int payload_size) {

    char haystack[payload_size+1];
    const char needle[] = "\r\nReferer:";
    char *p = NULL;
    int i;

    strncpy(haystack, payload, payload_size);
    haystack[payload_size]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return "\0";

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        referer[0] = '\0';
    else {
        p += 2; // skip \r\n
        for(i=0; i<MAX_REFERER_LEN && (p+i) < &(haystack[payload_size]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            referer[i]=*(p+i);
        }
        referer[i]='\0';
    }

    return referer;
}

char *get_ref_host(char* refhost, const char *payload, int payload_size) {

    char haystack[payload_size+1];
    const char needle[] = "\r\nReferer:";
    char *p = NULL;
    int i;

    char referer[MAX_HOST_LEN+1];

    strncpy(haystack, payload, payload_size);
    haystack[payload_size]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return "\0";

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        referer[0] = '\0';
    else {
        p += 2; // skip \r\n
        for(i=0; i<MAX_HOST_LEN && (p+i) < &(haystack[payload_size]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            referer[i]=*(p+i);
        }
        referer[i]='\0';
    }

    char* pos = strstr(referer,"://");
    if(pos == NULL)
        return NULL;

    pos += strlen("://"); // skip '://'
    while(*pos != '/' && *pos != '\0') {
        *refhost = *pos;
        pos++;
        refhost++;
    }
    *refhost = '\0';

    return refhost;
}

char *get_user_agent(char* ua, const char *payload, int payload_size) {

    char haystack[payload_size+1];
    const char needle[] = "\r\nUser-Agent:";
    char *p = NULL;
    int i;

    strncpy(haystack, payload, payload_size);
    haystack[payload_size]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return "\0";

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        ua[0] = '\0';
    else {
        p += 2; // skip \r\n
        for(i=0; i<MAX_UA_LEN && (p+i) < &(haystack[payload_size]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            ua[i]=*(p+i);
        }
        ua[i]='\0';
    }

    // TODO(Roberto): read strings from a config file
    // replace UA string with generalized UA
    if(strstr(ua,"Edge"))
        strcat(ua," Edge ");
    if(strstr(ua,"Chrome"))
        strcat(ua," Chrome ");
    if(strstr(ua,"Firefox"))
        strcat(ua," Firefox ");
    if(strstr(ua,"MSIE"))
        strcat(ua," MSIE ");
    if(strstr(ua,"Safari"))
        strcat(ua," Safari ");
    if(strstr(ua,"Opera"))
        strcat(ua," Opera ");
    if(strstr(ua,"Linux"))
        strcat(ua," Linux ");
    if(strstr(ua,"Android"))
        strcat(ua," Android ");
    if(strstr(ua,"Windows"))
        strcat(ua," Windows ");
    if(strstr(ua,"iPhone"))
        strcat(ua," iPhone ");
    if(strstr(ua,"Mac OS X"))
        strcat(ua," Mac OS X ");
    if(strstr(ua,"Mobile"))
        strcat(ua," Mobile ");

    return ua;
}

int is_complete_http_resp_header(const struct tcp_flow *tflow) {
    if(tflow->sc_payload == NULL)
        return 0;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Checking if complete HTTP header\n");
        fflush(stdout);
        printf("lenght of tflow->sc_payload = %zu, tflow->sc_payload_size = %d \n", strlen(tflow->sc_payload),tflow->sc_payload_size);
        fflush(stdout);
    }
    #endif

    const char needle[] = "\r\n\r\n";
    int needle_len = 4;

    if(strnlen(tflow->sc_payload,needle_len) < needle_len)
        return 0;

    char *p = boyermoore_search(tflow->sc_payload,needle);

    if(p != NULL)
        return 1;

    return 0;
}



int get_resp_hdr_length(const char *payload, int payload_size) {

    #define HDR_SEARCH_LIMIT 3*1024 // we expect to find "\r\n\r\n" withing first 3kB

    int search_limit = MIN(HDR_SEARCH_LIMIT,payload_size);
    char haystack[search_limit+1];
    const char needle[] = "\r\n\r\n";
    char *p = NULL;

    strncpy(haystack, payload, search_limit);
    haystack[search_limit]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return -1;

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        return -1;
    else 
        return p-haystack+strlen(needle);
}



int get_content_length(const char *payload, int payload_size) {

    #define MAX_CONTENTLENGTH_LEN 40
    #define CL_SEARCH_LIMIT 3*1024 // we expect to find the content lenght withing first 3kB

    int cl_search_limit = MIN(CL_SEARCH_LIMIT,payload_size);
    char contentlen_str[MAX_CONTENTLENGTH_LEN+1];
    char haystack[cl_search_limit+1];
    const char needle[] = "\r\nContent-Length:";
    char *p = NULL;
    int i;

    strncpy(haystack, payload, cl_search_limit);
    haystack[cl_search_limit]='\0'; // just to be safe...

    if(strlen(haystack) < strlen(needle))
        return -1;

    p = boyermoore_search(haystack,needle);
    
    if(p == NULL) 
        return -1;
    else {
        p += 2; // skip \r\n

        for(i=0; i<MAX_CONTENTLENGTH_LEN && (p+i) < &(haystack[cl_search_limit]); i++) {
            if(*(p+i) == '\r' || *(p+i) == '\n')
                break;
            contentlen_str[i]=*(p+i);
        }
        contentlen_str[i]='\0';
    }


    // parse contentlen_str and return an integer
    int k = strlen(contentlen_str);
    p = contentlen_str;

    while((*p)!=':' && p<p+k)
        p++;
    p++; // skip ':'

    return atoi(p);

}


int parse_content_length_str(const char *cl_str) {

   int k = strlen(cl_str);
   char *p = (char*)cl_str;

   while((*p)!=':' && p<p+k) 
       p++;

   return atoi(p);

}


// This function returns FILE_FOUND if we find a possible file of interest
// If the magic number is found, we will attempt to reconstruct and log the file
// We can then check offline if the downloaded file is really an interesting file, otherwise we delete it
int contains_interesting_file(const struct tcp_flow *tflow) {

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Checking if response contains file of interest\n");
        fflush(stdout);
    }
    #endif

    if(tflow->sc_payload == NULL)
        return FILE_WAIT_FOR_RESP_BODY;

    #define MIN_FILE_PAYLOAD_SIZE 14
    if(tflow->sc_payload_size < MIN_FILE_PAYLOAD_SIZE)
	    return FILE_WAIT_FOR_RESP_BODY;

    if(strncmp(tflow->sc_payload,"HTTP/",5)!=0) // payload must begin with "HTTP/", otherwise it's not a valid HTTP response
        return FILE_NOT_FOUND;

    #define HTTP_200_OFFSET 8 // strlen("HTTP/x.x") == 8
    if(strncmp(tflow->sc_payload+HTTP_200_OFFSET," 200 ",5)!=0) // we only accept 200 OK responses (check for "200" right after "HTTP/x.x")
        return FILE_NOT_FOUND;

    int resp_hdr_len = get_resp_hdr_length(tflow->sc_payload, tflow->sc_payload_size);
    if(resp_hdr_len <= 0) // at this stage, this should never happen!
        return FILE_NOT_FOUND;

    int resp_body_len = tflow->sc_payload_size - resp_hdr_len;

    //////////////////////////////////////////////
    // CHECK FOR THE PRESENCE OF INTERESTING FILES
    #define MIN_MAGIC_LEN 2
    #define MAX_MAGIC_LEN 8

    if(resp_body_len > MIN_MAGIC_LEN) {
        char *pp = tflow->sc_payload+resp_hdr_len; // point pp to the beginning of the HTTP response body

        #define PE_MAGIC_LEN 2
        if(find_pe_files && resp_body_len>=PE_MAGIC_LEN) {
            // check for possible presence of a Windows PE file
            // This needs to be verified offline (e.g., search for "PE" at right offset)
            if(pp[0] == 'M' && pp[1] == 'Z') {
                printf("==> Found possible PE file!\n");
                return FILE_FOUND;
            }
        }

        #define DMG_MAGIC_LEN 4
        if(find_dmg_files && resp_body_len>=DMG_MAGIC_LEN) { 
            // check for possible presence of DMG file
            // This actually also finds Zlib and BZip compressed files!
            // We need to verify offline if this is actually a DMG file (e.g., check for "koly")
            // see http://newosxbook.com/DMG.html
            
            if(pp[0] == (char)0x78) {
                // 0x789C   zlib compressed
                // 0x78DA   zlib compressed
                // 0x7801   zlib compressed
                if(pp[1] == (char)0x01 || pp[1] == (char)0xDA || pp[1] == (char)0x9C) {
                    printf("==> Found possible DMG file!\n");
                    return FILE_FOUND;
                }
            }

            if(strncmp(pp,"BZh",3)==0) {
                // BZh      BZip compressed
                // see https://github.com/devttys0/binwalk/blob/master/src/magic/compressed 
                printf("==> Found possible DMG file!\n");
                return FILE_FOUND;
            }
        }

        #define JAR_MAGIC_LEN 7
        if(find_jar_files && resp_body_len>=JAR_MAGIC_LEN) {
            // This helps us find JARs and APKs
            // see http://www.garykessler.net/library/file_sigs.html
            // JAR (first 7 bytes): 50 4B 03 04 14 00 08
            //                      50 4b 03 04 0a 00 00
            char jar_magic1[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x08};
            char jar_magic2[] = {0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00, 0x00};
            int k;

            int jar_magic1_found=TRUE;
            for(k=0; k<JAR_MAGIC_LEN; k++) {
                // printf("%x %x", pp[k], jar_magic1[k]);
                if(pp[k] != jar_magic1[k]) {
                    jar_magic1_found = FALSE;
                    break;
                }
            }
            if(jar_magic1_found) {
                printf("==> Found possible JAR file!\n");
                return FILE_FOUND;
            }

            int jar_magic2_found=TRUE;
            for(k=0; k<JAR_MAGIC_LEN; k++) {
                // printf("%x %x", pp[k], jar_magic2[k]);
                if(pp[k] != jar_magic2[k]) {
                    jar_magic2_found = FALSE;
                    break;
                }
            }
            if(jar_magic2_found) {
                printf("==> Found possible JAR file!\n");
                return FILE_FOUND;
            }
        }

        #define MSDOC_MAGIC_LEN 8
        if(find_msdoc_files && resp_body_len>=MSDOC_MAGIC_LEN) {
            // This helps us find DOC(X), PPT(X), XLS(X) etc.
            // see http://www.garykessler.net/library/file_sigs.html
            // DOCX, PPTX, XLSX: 50 4B 03 04 14 00 06 00
            // DOC, PPT, XLS:    D0 CF 11 E0 A1 B1 1A E1
            char msdocx_magic[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00};
            char msdoc_magic[]  = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
            int k;

            int msdocx_magic_found = TRUE;
            for(k=0; k<MSDOC_MAGIC_LEN; k++) {
                if(pp[k] != msdocx_magic[k]) {
                    msdocx_magic_found = FALSE;
                    break;
                }
            }
            if(msdocx_magic_found) {
                printf("==> Found possible MS OFFICE file!\n");
                return FILE_FOUND;
            }

            int msdoc_magic_found = TRUE;
            for(k=0; k<MSDOC_MAGIC_LEN; k++) {
                if(pp[k] != msdoc_magic[k]) {
                    msdoc_magic_found = FALSE;
                    break;
                }
            }
            if(msdoc_magic_found) {
                printf("==> Found possible MS OFFICE file!\n");
                return FILE_FOUND;
            }
        }

        #define ZIP_MAGIC_LEN 4
        if(find_zip_files && resp_body_len>=ZIP_MAGIC_LEN) {
            // This helps us find ZIP, JAR, APK, etc., and any Zip compresed file in general 
            // (as a side effect, it will also find DOCX, PPTX, XLSX, XAP etc.)
            if(pp[0]=='P' && pp[1]=='K' && pp[2]==(char)0x03 && pp[3]==(char)0x04) {
                printf("==> Found possible ZIP file!\n");
                return FILE_FOUND;
            }
        }

        #define SWF_MAGIC_LEN 3
        if(find_swf_files && resp_body_len>=SWF_MAGIC_LEN) {
            // This helps us find Flash SWF files
            // see http://www.garykessler.net/library/file_sigs.html
                // 46 57 53
                // 43 57 53
                // 5A 57 53
            if(pp[0] == (char)0x46 || pp[0] == (char)0x43 || pp[0] == (char)0x5A) {
                if(pp[1] == (char)0x57 || pp[1] == (char)0x53) {
                    printf("==> Found possible SWF file!\n");
                    return FILE_FOUND;
                }
            }
        }

        #define RAR_MAGIC_LEN 4
        if(find_rar_files && resp_body_len>=RAR_MAGIC_LEN) {
            // Rar archives
            if(strncmp(pp,"Rar!",4)==0) {
                printf("==> Found possible RAR file!\n");
                return FILE_FOUND;
            }
        }

        #define ELF_MAGIC_LEN 4
        if(find_elf_files && resp_body_len>=ELF_MAGIC_LEN) {
            // ELF unix/linux executable files
            if(pp[0]==(char)0x7F && strncmp(pp+1,"ELF",3)==0) {
                printf("==> Found possible ELF file!\n");
                return FILE_FOUND;
            }
        }

        #define PDF_MAGIC_LEN 4
        if(find_pdf_files && resp_body_len>=PDF_MAGIC_LEN) {
            // PDFs
            if(strncmp(pp,"%PDF",PDF_MAGIC_LEN)==0) {
                printf("==> Found possible PDF file!\n");
                return FILE_FOUND;
            }
        }

        if(resp_body_len >= MAX_MAGIC_LEN)
            // we return FILE_NOT_FOUND only if all magic numbers have had a chance to be tested
            // otherwise we will wait for more bytes to be added to the payload (FILE_WAIT_FOR_RESP_BODY)
            return FILE_NOT_FOUND;
    }
    //////////////////////////////////////////////

    
    return FILE_WAIT_FOR_RESP_BODY;
}






// looks for gaps in the list of TCP sequence numbers
// returns TRUE is gaps are found
short is_missing_flow_data(seq_list_t *l, int flow_payload_len) {
    // detect gaps in the sequence numbers

    seq_list_entry_t *e;
    u_int seq_num, psize, m;
    u_int max_seq_num, init_seq_num;
    short gap_detected;
    int estimated_flow_payload_len;


    // check if this is a non-empy seq_list
    if(l == NULL)
        return CORRUPT_MISSING_DATA_INVALID_SEQ_LIST;
    if(seq_list_head(l) == NULL)
        return CORRUPT_MISSING_DATA_INVALID_SEQ_LIST;

    // get the max sequence number in the list
    // notice that the list is not ordered; packet (seq_num, psize) pairs are stored in order of arrival
    // seq_num = TCP sequence number of Server->Client segment
    // psize = payload size of Server->Client TCP segment
    seq_list_restart_from_head(l); // makes sure we start from the head of the list
    e = seq_list_next(l);
    if(e == NULL) // This should never happen; if it does, something is very wrong!
        return CORRUPT_MISSING_DATA_INVALID_SEQ_LIST;

    init_seq_num = seq_list_get_seq_num(e);
    max_seq_num = 0;
    while(e != NULL) {
        seq_num = seq_list_get_seq_num(e);
        psize = seq_list_get_payload_size(e);
        m = seq_num+psize;
        if(m > max_seq_num) {
            max_seq_num = m;
        }

        e = seq_list_next(l);
    }

    estimated_flow_payload_len = max_seq_num - init_seq_num;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        // seq_list_print(l);
        printf("max_seq_num = %u  ", max_seq_num);
        printf("flow_payload_len = %u \n", flow_payload_len);
        printf("estimated content length = %u \n", estimated_flow_payload_len);
        fflush(stdout);
    }
    #endif

    if(estimated_flow_payload_len < flow_payload_len) // if true, it means we are missing some bytes
        return CORRUPT_MISSING_DATA_EST_LEN_TOO_SHORT; 
    if(estimated_flow_payload_len > flow_payload_len) // this should be impossible, something went really wrong!
        return CORRUPT_MISSING_DATA_EST_LEN_TOO_LONG; // not really missing data; signals a problem in the file reconstruction from which we cannot recover
        // TODO: maybe we should return an error code here, rather than TRUE/FALSE


    seq_list_entry_t *s, *s_gap;
    s = NULL; // we need to initialize s, otherwise we risk to use an uninitialized pointer later...
    s_gap = NULL; // we need to initialize s_gap, otherwise we risk to use an uninitialized pointer later...

    seq_list_restart_from_head(l); // makes sure we start from the head of the list
    s = seq_list_next(l); // set s to point to the first element in the list
    if(s == NULL) // This should never happen; if it does, something is very wrong!
        return CORRUPT_MISSING_DATA_INVALID_SEQ_LIST;

    u_int next_seq_num = seq_list_get_seq_num(s);
    u_int old_next_seq_num = next_seq_num;
    u_int payload_size = 0;


    #define MAX_LOOPS_KILL_SWITCH 100000 // safety guard to avoid infinite loops in case of an undetected bug in the gap finding algorithm 
    u_int loop_count = 0;

    gap_detected = TRUE;
    while(s != NULL && next_seq_num < max_seq_num && gap_detected)  {

        // safety guard to avoid infinite loops in case of an undetected bug in the gap finding algorithm
        loop_count++;
        if(loop_count >= MAX_LOOPS_KILL_SWITCH) {
            printf("MAX_LOOPS_KILL_SWITCH!\n");
            fflush(stdout);
            return CORRUPT_MISSING_DATA_TRIGGERED_KILL_SWITCH;
        }
        /////////////////////////////////////////
        
        // prepare for next iteration
        gap_detected = FALSE;
        s_gap = NULL;
        old_next_seq_num = next_seq_num;

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Next Seq = %u\n", next_seq_num);
            printf("Max Seq = %u\n", max_seq_num);
            fflush(stdout);
        }
        #endif

        while(s != NULL) { // at every itration, finds the lagest "contiguous" next_seq_num

            // safety guard to avoid infinite loops in case of an undetected bug in the gap finding algorithm
            loop_count++;
            if(loop_count >= MAX_LOOPS_KILL_SWITCH) {
                printf("MAX_LOOPS_KILL_SWITCH!\n");
                fflush(stdout);
                return CORRUPT_MISSING_DATA_TRIGGERED_KILL_SWITCH;
            }
            /////////////////////////////////////////

            seq_num = seq_list_get_seq_num(s);
            payload_size = seq_list_get_payload_size(s);

            if(seq_num <= next_seq_num && seq_num+payload_size > next_seq_num) { // NO GAP (YET)
                next_seq_num = seq_num+payload_size;
            }
            else if(!gap_detected && seq_num > next_seq_num) {
                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Seq Num = %u\n", seq_num);
                    printf("Payload Size = %u\n", payload_size);
                    fflush(stdout);
                }
                #endif

                gap_detected = TRUE;   
                s_gap = s; // later we will restart another loop from this list element, to save time
            }

            s = seq_list_next(l);
        }

        if(next_seq_num <= old_next_seq_num || next_seq_num >= max_seq_num) { // no progress in this cycle, or we reached the end

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {    
                printf("+++ No progress filling the gaps!\n");
                printf("+++ Next Seq = %u\n", next_seq_num);
                printf("+++ Max Seq = %u\n", max_seq_num);
                printf("+++ GAP = %u\n", gap_detected);
                fflush(stdout);
            }
            #endif

            break; 
        }

        // if we did make progress in filling the gaps in the previous loop
        // but a gap still remains, we re-explore the list to see if we can fill it
        if(gap_detected) {
            // start another loop to see if we can fill the gaps
            if(s_gap != NULL) {
                seq_list_restart_from_element(l,s_gap); // we restart exploring the list of sequence numbers from the gap
                s = seq_list_next(l);
            }
            else s = NULL;
        }

    }

    // if gap_detected remains TRUE after scanning the sequence numbers list (possibly) muliple times
    // then it means that we are really missing data
    if(gap_detected) { // detected missing data
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) 
	        printf("DETECTED MISSING DATA\n");
        #endif

        return CORRUPT_MISSING_DATA;
    }

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE)
        printf("NO MISSING DATA\n");
    #endif

    return FALSE; // everything looks fine!
}



void dump_pe(struct tcp_flow *tflow) {
// make a copy of all buffers
// free mamory that is not needed

    if(tflow->sc_payload == NULL)
        return;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Preparing data for dumping: %s\n",tflow->anon_cs_key);
        fflush(stdout);
    }
    #endif

    struct dump_payload_thread *tdata;
    pthread_t thread_id;

    tdata = (struct dump_payload_thread*)malloc(sizeof(struct dump_payload_thread));
    if(tdata == NULL)
        return;

    sprintf(tdata->dump_file_name,"%s-%d",tflow->anon_cs_key,tflow->http_request_count);
    strcpy(tdata->url,tflow->url);
    strcpy(tdata->host,tflow->host);
    strcpy(tdata->referer,tflow->referer);
    tdata->file_payload = tflow->sc_payload;
    tdata->file_payload_size = tflow->sc_payload_size;
    tdata->corrupt_pe = tflow->corrupt_pe;
    tdata->sc_seq_list = tflow->sc_seq_list;

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Creating dumping thread: %s\n",tflow->anon_cs_key);
        fflush(stdout);
    }
    #endif
    
    tflow->sc_payload = NULL; // avoids buffer to be freed by main thread
    tflow->sc_seq_list = NULL; // prevents a possible double free

    pthread_create(&thread_id,NULL,dump_file_thread,(void*)tdata);
    pthread_detach(thread_id); // this allows for the thread data structures to be reclaimed as soon as thread ends

}

void *dump_file_thread(void* d) {
    struct dump_payload_thread* tdata = (struct dump_payload_thread*)d;

    char ts_str[TS_STR_LEN+1];
    itoa(time(NULL),ts_str);

    ////////////////////////////////////
    // Notify all listening processes that http request list 
    // for srcip must be dumpted
    char notify_fname[NOTIFY_FNAME_LEN+1];

    notify_fname[0]='\0';
    strcat(notify_fname,HTTPREQLIST_PREFIX);
    strcat(notify_fname,"dump");
    strcat(notify_fname,"_");
    strcat(notify_fname,ts_str);
    strcat(notify_fname,"_");
    strncat(notify_fname,tdata->dump_file_name,MAX_KEY_LEN+1);

    create_dev_shm_tmp_file(notify_fname);
    ////////////////////////////////////


    ///////////////////////////////////
    // Executable file dump
    #define FNAME_LEN MAX_DUMPDIR_LEN+MAX_NIC_NAME_LEN+MAX_KEY_LEN+3
    char fname[FNAME_LEN];
    char tmp_fname[FNAME_LEN+TMP_SUFFIX_LEN+1];
    FILE* dump_file;

    if(tdata == NULL || tdata->file_payload == NULL)
        pthread_exit(NULL);

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Preparing dump file...\n");
        fflush(stdout);
    }
    #endif

    fname[0]='\0';
    strncat(fname,dump_dir,MAX_DUMPDIR_LEN);
    strncat(fname,"/",1);
    if(nic_name != NULL) {
        strncat(fname,nic_name,MAX_NIC_NAME_LEN);
        strncat(fname,"~",1);
    }
    strncat(fname,tdata->dump_file_name,MAX_KEY_LEN);


    strncpy(tmp_fname,fname,FNAME_LEN);
    strncat(tmp_fname,".tmp",TMP_SUFFIX_LEN);
    if((dump_file = fopen(tmp_fname,"wb")) == NULL) {
        fprintf(stderr,"Cannot write to file %s\n",tmp_fname);
	    perror("--> ");
        fflush(stderr);
    }
    printf("Writing to file %s\n",tmp_fname);
    fflush(stdout);

    #ifdef FILE_DUMP_DEBUG    
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Dumping to file: %s\n",tdata->dump_file_name);
        fflush(stdout);
    }
    #endif


    fwrite("% ", sizeof(char), 2, dump_file);
    fwrite(ts_str, sizeof(char), strlen(ts_str), dump_file);
    fwrite("\n", sizeof(char), 1, dump_file);
    fwrite("% ", sizeof(char), 2, dump_file);
    fwrite(tdata->dump_file_name, sizeof(char), strlen(tdata->dump_file_name), dump_file);
    fwrite("\n", sizeof(char), 1, dump_file);
    fwrite("% ", sizeof(char), 2, dump_file);
    fwrite(tdata->url, sizeof(char), strlen(tdata->url), dump_file);
    fwrite("\n", sizeof(char), 1, dump_file);
    fwrite("% ", sizeof(char), 2, dump_file);
    fwrite(tdata->host, sizeof(char), strlen(tdata->host), dump_file);
    fwrite("\n", sizeof(char), 1, dump_file);
    fwrite("% ", sizeof(char), 2, dump_file);
    fwrite(tdata->referer, sizeof(char), strlen(tdata->referer), dump_file);
    fwrite("\n", sizeof(char), 1, dump_file);

    int httphdrlen = get_resp_hdr_length(tdata->file_payload, tdata->file_payload_size);
    int contentlen = get_content_length(tdata->file_payload, tdata->file_payload_size);
    int flow_payload_len = httphdrlen + contentlen;

    #ifdef FILE_DUMP_DEBUG    
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("HTTP Response Header Length: %d\n", httphdrlen);
        printf("HTTP Response Body Length: %d\n", contentlen);
    }
    #endif

    if(contentlen <= 0 || httphdrlen <= 0) { // this should never happen, but we check anyway
        tdata->corrupt_pe = CORRUPT_INVALID_RESPONSE_LEN; 
        printf("CORRUPT_INVALID_RESPONSE_LEN (contentlen <= 0 || httphdrlen <= 0)\n");
        fflush(stdout);
    }

    if(flow_payload_len > tdata->file_payload_size) { // if true, we are clearly missing data
	    tdata->corrupt_pe = CORRUPT_INVALID_RESPONSE_LEN;
        printf("CORRUPT_INVALID_RESPONSE_LEN (flow_payload_len = %d > tdata->file_payload_size = %d)\n", flow_payload_len, tdata->file_payload_size);
        fflush(stdout);
    }

    // check if there is any gap in the list of TCP sequence numbers
    // also check if total size of reconstructed payloads matches the expected HTTP Content Lenght
    short missing_data = FALSE;
    if(tdata->corrupt_pe != CORRUPT_INVALID_RESPONSE_LEN) {
        missing_data = is_missing_flow_data(tdata->sc_seq_list, flow_payload_len);
        printf("IS_MISSING_FLOW_DATA returned %d\n", missing_data);
        fflush(stdout);
        if(missing_data)
            tdata->corrupt_pe = CORRUPT_MISSING_DATA;
    }


    #ifdef FILE_DUMP_DEBUG    
    if(debug_level >= VERY_VERY_VERBOSE) {
        if(tdata->corrupt_pe)
            printf("IS CORRUPT\n");
        else
            printf("NOT CORRUPT\n");
    }

    printf("\n===\n");
    fflush(stdout);
    #endif


    #define CORRUPT_FILE_ALERT "CORRUPT_FILE"
    fwrite("% ", sizeof(char), 2, dump_file);
    // if(tdata->corrupt_pe) { // This is likely too conservative, and may generate many false positives
    if(tdata->corrupt_pe == CORRUPT_MISSING_DATA || tdata->corrupt_pe == CORRUPT_INVALID_RESPONSE_LEN) { 
        // we should trust that our missing data detection algorithm does a good job!
        fwrite(CORRUPT_FILE_ALERT, sizeof(char), strlen(CORRUPT_FILE_ALERT), dump_file);

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("THIS IS A CORRUPTED BINARY!\n");
            printf("tdata->corrupt_pe = %d , is_missing_flow_data = %d\n", tdata->corrupt_pe, missing_data);
            fflush(stdout);
        }
        #endif
    }
    fwrite("\n", sizeof(char), 1, dump_file);

    fwrite("\n", sizeof(char), 1, dump_file);
    fwrite(tdata->file_payload, sizeof(char), tdata->file_payload_size, dump_file);
    fclose(dump_file);

    // rename temporary dump file
    int ren = rename(tmp_fname, fname);
    if(ren < 0) {
        fprintf(stderr,"Unable to rename %s\n",tmp_fname);
        perror("--> ");
        fflush(stderr);
    }
    printf("Renamed dump file to %s\n", fname);
    fflush(stdout);
    

    #ifdef FILE_DUMP_DEBUG    
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Closed dumped file: %s\n",tdata->dump_file_name);
        fflush(stdout);
    }
    #endif

    // free the memory
    free(tdata->file_payload);
    seq_list_destroy(tdata->sc_seq_list, TRUE);
    tdata->sc_seq_list = NULL;


    free(tdata);

    #ifdef FILE_DUMP_DEBUG    
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Closing thread after freeing tdata: %s\n",tdata->dump_file_name);
        fflush(stdout);
    }
    #endif

    ////////////////////////////////////
    // Remove file used for notification
    sleep(3); // waits a moment to make sure inotify realizes a file was previously written

    remove_dev_shm_tmp_file(notify_fname);
    ////////////////////////////////////
    
    pthread_exit(NULL);
}

 
void update_flow(struct tcp_flow *tflow, const struct tcp_header *tcp, const char *payload, const int payload_size) {

    if(tflow == NULL) // checking just for sure...
        return;

    if(tflow->sc_payload == NULL) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("Flow %s payload is being initialized \n",tflow->anon_cs_key);
            fflush(stdout);
        }
        #endif

        tflow->sc_init_seq = ntohl(tcp->th_seq);
        tflow->sc_payload = (char*)malloc((INIT_SC_PAYLOAD+1)*sizeof(char));
        if(tflow->sc_payload == NULL)
            return;

        memset(tflow->sc_payload, 0, INIT_SC_PAYLOAD+1);
        tflow->sc_payload_size = 0;
        tflow->sc_payload_capacity = INIT_SC_PAYLOAD;
        tflow->sc_num_payloads = 0;
        tflow->sc_seq_list = seq_list_init();
        tflow->corrupt_pe = FALSE;
    }

    if(payload_size == 0)
        return;

    tflow->sc_num_payloads++; //counts number of payload (for now including duplicate, we'll change it later)

    #ifdef FILE_DUMP_DEBUG
    if(debug_level >= VERY_VERY_VERBOSE) {
        printf("Flow %s is being updated. Flow state = %d \n",tflow->anon_cs_key, tflow->flow_state);
        fflush(stdout);
    }
    #endif

    int p = ntohl(tcp->th_seq) - tflow->sc_init_seq;
    if(p < 0) // this should not be possible, skip it!
        return; 


    // If we are wiating for a header of possible file, we update the flow payload but do not allocate any more memory
    if(tflow->flow_state == FLOW_HTTP_RESP_HEADER_WAIT || tflow->flow_state == FLOW_HTTP_RESP_MAGIC_WAIT) {
        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("p=%d, th_seq=%u, sc_init_seq=%u\n",p,ntohl(tcp->th_seq),tflow->sc_init_seq);
            fflush(stdout);
        }
        #endif

        // if we have enough initial memory allocated to this flow, we update sequence number, payload content, etc.
        // otherwise, we don't do anything because we don't need to keep tracking a flow that has no sign of carrying 
        // a file of interest within the initial INIT_SC_PAYLOAD capacity
        if(p+payload_size < tflow->sc_payload_capacity) {
            // memcpy(&(tflow->sc_payload[p]), payload, MIN(tflow->sc_payload_capacity - p - 1, payload_size));
            memcpy(&(tflow->sc_payload[p]), payload, payload_size);
            seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_seq), payload_size); 

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Called memcpy...\n");
                // printf("Payload for %s:\n%s\n\n",tflow->anon_cs_key, tflow->sc_payload);
                // printf("SC SEQ LIST = ");
                // seq_list_print(tflow->sc_seq_list);
                fflush(stdout);
            }
            #endif

            if(p+payload_size > tflow->sc_payload_size) // updates where the sc_payload ends
                tflow->sc_payload_size = p+payload_size;

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("tflow->sc_payload_size = %d\n",tflow->sc_payload_size);
                fflush(stdout);
            }
            #endif

        }

        return;
    }

    // if we are currently tracking a file download, then we should allow for increasing memory allocation to keep reconstructing the flow payload
    else if(tflow->flow_state == FLOW_HTTP_RESP_MAGIC_FOUND) {
        if(p+payload_size < tflow->sc_payload_capacity) {
            memcpy(&(tflow->sc_payload[p]), payload, payload_size);
            seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_seq), payload_size);

            if(p+payload_size > tflow->sc_payload_size) // updates where the sc_payload ends
                tflow->sc_payload_size = p+payload_size;

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Updated tflow paylaod without reallocating memory: %s\n",tflow->anon_cs_key);
                // printf("SC SEQ LIST = ");
                // seq_list_print(tflow->sc_seq_list);
                fflush(stdout);
            }
            #endif

        }
        else {


            int realloc_size = MAX(REALLOC_SC_PAYLOAD, payload_size);

            if(p+payload_size > tflow->sc_payload_capacity+realloc_size) 
                // something wrong here... probably extreme packet reordering or loss... skip it!
                return;

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Need to reallocate %d tflow paylaod memory: %s\n",realloc_size,tflow->anon_cs_key);
                printf("Current payload capacity = %d\n",tflow->sc_payload_capacity);
                printf("Payload pointer = %p\n",tflow->sc_payload);
                fflush(stdout);
            }
            #endif

            tflow->sc_payload_capacity += realloc_size;

            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("New capacity = %d\n",tflow->sc_payload_capacity);
                fflush(stdout);
            }
            #endif

            // tflow->sc_payload = realloc(tflow->sc_payload, tflow->sc_payload_capacity+1);

            if(tflow->sc_payload!=NULL) {
                char *tmp_ptr = tflow->sc_payload;
                tflow->sc_payload = NULL;
                tflow->sc_payload = malloc((tflow->sc_payload_capacity+1)*sizeof(char));

                if(tflow->sc_payload == NULL)
                    return;

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Reallocated tflow paylaod memory: %s\n",tflow->anon_cs_key);
                    printf("Old payload pointer = %p\n",tmp_ptr);
                    printf("New payload pointer = %p\n",tflow->sc_payload);
                    fflush(stdout);
                }
                #endif

                memset(tflow->sc_payload, 0, (tflow->sc_payload_capacity+1));

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Initialized new paylaod memory: %s\n",tflow->anon_cs_key);
                    fflush(stdout);
                }
                #endif

                memcpy(tflow->sc_payload, tmp_ptr, tflow->sc_payload_size);

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Copied paylaod memory: %s\n",tflow->anon_cs_key);
                    printf("Freeing old payload pointer = %p\n",tmp_ptr);
                    fflush(stdout);
                }
                #endif

                free(tmp_ptr);

                #ifdef FILE_DUMP_DEBUG
                if(debug_level >= VERY_VERY_VERBOSE) {
                    printf("Freed old payload memory: %s\n",tflow->anon_cs_key);
                    fflush(stdout);
                }
                #endif

            }


            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Initialized new paylaod memory: %s\n",tflow->anon_cs_key);
                fflush(stdout);
            }
            #endif

            memcpy(&(tflow->sc_payload[p]), payload, payload_size);
            seq_list_insert(tflow->sc_seq_list, ntohl(tcp->th_seq), payload_size);

            if(p+payload_size > tflow->sc_payload_size) // updates where the sc_payload ends
                tflow->sc_payload_size = p+payload_size;


            #ifdef FILE_DUMP_DEBUG
            if(debug_level >= VERY_VERY_VERBOSE) {
                printf("Updated tflow paylaod memory reallocation: %s\n",tflow->anon_cs_key);
                // printf("SC SEQ LIST = ");
                // seq_list_print(tflow->sc_seq_list);
                fflush(stdout);
            }
            #endif

        } 

        #ifdef FILE_DUMP_DEBUG
        if(debug_level >= VERY_VERY_VERBOSE) {
            printf("File %s has new payload size %d\n",tflow->anon_cs_key, tflow->sc_payload_size);
            fflush(stdout);
        }
        #endif
    }
}


void reset_flow_payload(struct tcp_flow *tflow) {
    if(tflow->sc_payload==NULL)
        return;

    free(tflow->sc_payload);
    tflow->sc_payload = NULL;

    if(tflow->sc_seq_list != NULL) {
        seq_list_destroy(tflow->sc_seq_list, FALSE);
        tflow->sc_seq_list = NULL;
    }
}


// using thing instead of sprintf because sprintf was causing strange problems...
void get_key(char *key, const char* pkt_src, const char *pkt_dst) {
    key[0]='\0';
    strcat(key,pkt_src);
    strcat(key,"-");
    strcat(key,pkt_dst);
    // printf("key = %s\n",key);

    return;    
}


/* itoa:  convert n to characters in s */
void itoa(int n, char *s) {
     int i, sign;
 
     if ((sign = n) < 0)  /* record sign */
         n = -n;          /* make n positive */
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     if (sign < 0)
         s[i++] = '-';
     s[i] = '\0';
     reverse(s);
}


/* reverse:  reverse string s in place */
void reverse(char *s) {
     int i, j;
     char c;
 
     for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
         c = s[i];
         s[i] = s[j];
         s[j] = c;
     }
}


void print_http_req_value(void* v, FILE* f) {
    http_req_value_t* h = (http_req_value_t*)v;
    fprintf(f,"%lu.%lu | %s | %s | %s | %s\n", h->time.tv_sec, h->time.tv_usec, h->servip, h->host, h->refhost, h->ua);
}

void print_http_req_list(fifo_queue_t* q, FILE* f, time_t time_limit) {
    fifoq_reset_cursor(q);

    http_req_value_t* v = NULL;
    while((v = fifoq_get_next_value(q)) != NULL) { 
        if(v->time.tv_sec >= time_limit) 
            print_http_req_value(v,f);
    }
}

void fifoq_destroy_fn(void* q) {
    fifoq_destroy((fifo_queue_t*)q);
}

bool equal_httpreq(http_req_value_t* v1, http_req_value_t* v2) {

    if(v1==NULL || v2==NULL) {
        return false;
    }

    if(strcmp(v1->servip,v2->servip)==0) {
        if((v1->host == v2->host) || strcmp(v1->host,v2->host)==0) { 
            // (v1->refhost == v2->refhost) needed in case the two are NULL
            if((v1->refhost == v2->refhost) || strcmp(v1->refhost,v2->refhost)==0) {
                if((v1->ua == v2->ua) || (strcmp(v1->ua,v2->ua)==0)) {
                    return true;
                }
            }
        }
    }

    return false;
}


void* dump_httpreq_list_thread(void* notify_dir) {
    char* notify_dir_str = (char*)notify_dir;

    #define EVENT_SIZE sizeof(struct inotify_event)
    #define EVENT_BUF_LEN 1024*(EVENT_SIZE + 16) 

    int event_len, i = 0;
    int fd, wd;
    char buffer[EVENT_BUF_LEN];

    if((fd = inotify_init()) < 0) 
        perror("Error in inotify_init");
    if((wd = inotify_add_watch(fd, notify_dir_str, IN_CREATE)) < 0)
        perror("Error in inotify_add_watch");

    bool stop = false;
    while(!stop) {
        i = 0;

        if((event_len = read(fd, buffer, EVENT_BUF_LEN)) < 0) {
            perror("Error reading event bugger");
            break;
        }

        while(i<event_len) {
            struct inotify_event *e = (struct inotify_event*)&buffer[i];
            if(e->len > 0) {
                if((e->mask & IN_CREATE) && !(e->mask & IN_ISDIR)) {
                    printf("==NOTIFY== New file %s created in %s\n", e->name, notify_dir_str);
                    fflush(stdout);

                    if(str_starts_with(e->name,HTTPREQLIST_PREFIX)) {
                        printf("==NOTIFY== strstr: %s \n", e->name);
                        fflush(stdout);

                        // Preapre file name where to store http req list
                        char pidstr[12];
                        itoa(getpid(),pidstr);

                        char hf_fname[1024];
                        hf_fname[0] = '\0';
                        strcat(hf_fname,httpreq_track_dir);
                        strcat(hf_fname,e->name);
                        strcat(hf_fname,"__");
                        strcat(hf_fname,pidstr);
                        ////////////////////////

                        // NOTE(Roberto): the following calls make use of strtok
                        // and may alter the e->name string
                        time_t ts = get_time_from_httpreq_fname(e->name);
                        char* srcip = get_srcip_from_httpreq_fname(e->name);
                        ///////////////////////////////////

                        fifo_queue_t* q = NULL;
                        if(srcip!=NULL) {
                            pthread_mutex_lock(&glruc_q_mutex);
                            q = glruc_pop_value(glruc_q,srcip);
                            pthread_mutex_unlock(&glruc_q_mutex);
                        }

                        // TODO(Roberto): add time limit, instead of printing everything
                        if(q!=NULL && q->num_elements>0) {

                            FILE* hf = fopen(hf_fname,"w");
                            if(hf == NULL) {
                                fprintf(stderr,"Error while writing http req list to %s\n", hf_fname);
                                perror("===> Unable to open httpreq track file");
                                break;
                            }

                            fprintf(hf,"TS: %ld\n", ts);
                            fprintf(hf,"SRC_IP: %s\n", srcip);
                            fprintf(hf,"FORMAT: timestamp | server_ip | host | referrer | user_agent \n");
                            fflush(hf);

                            // TODO(Roberto): make time delta configurable
                            #define STORE_QUEUE_TIME_DELTA 300
                            time_t ts_limit = ts - STORE_QUEUE_TIME_DELTA;
                            print_http_req_list(q,hf,ts_limit);
                            // print_fifoq(q, print_http_req_value, hf);
                            fifoq_destroy(q);

                            fclose(hf);
                        }
                    }
                }
            }
            i += EVENT_SIZE + e->len;
        }

        // FIXME(Roberto): add mutex lock here, though it may be redundant
        stop = dump_httpreq_list_thread_must_exit;
        // remove mutex lock here
    }

    inotify_rm_watch(fd,wd);
    close(fd);

    pthread_exit(NULL);
}



///////////////////////////////////////////
#define DEV_SHM_PATH "/dev/shm/"
void create_dev_shm_tmp_file(char* fname) {
    char pidstr[12];
    char fpath[strlen(DEV_SHM_PATH)+strlen(fname)+1];
    FILE* dump_httpreq_list_notify_file;

    fpath[0]='\0';
    strcat(fpath,DEV_SHM_PATH);
    strcat(fpath,fname);

    itoa(getpid(),pidstr);
    strcat(fpath,"__");
    strcat(fpath,pidstr);

    if((dump_httpreq_list_notify_file = fopen(fpath,"wb")) == NULL) {
        fprintf(stderr,"Cannot write to notify file %s\n",fpath);
        perror("--> ");
        fflush(stderr);
    }
    fclose(dump_httpreq_list_notify_file);
    printf("Wrote notify file: %s\n",fpath);
    fflush(stdout);
}

void remove_dev_shm_tmp_file(char* fname) {
    char pidstr[12];
    char fpath[strlen(DEV_SHM_PATH)+strlen(fname)+1];

    fpath[0]='\0';
    strcat(fpath,DEV_SHM_PATH);
    strcat(fpath,fname); 
 
    itoa(getpid(),pidstr);
    strcat(fpath,"__");
    strcat(fpath,pidstr);

    if(remove(fpath)!=0) {
        fprintf(stderr, "Cannot remove notify file %s\n", fpath);
    }
    printf("Removed notify file: %s\n",fpath);
    fflush(stdout);
}

void interrupt_dump_httpreq_list_thread() {
    dump_httpreq_list_thread_must_exit = true;
    // will make inotify read infinite loop treminate
    create_dev_shm_tmp_file("dump_httpreq_list_thread_must_exit");
    sleep(1);
    remove_dev_shm_tmp_file("dump_httpreq_list_thread_must_exit");
}

char* get_srcip_from_httpreq_fname(char* fname) {
    //fname format:
    //httpreqlist-trigger_timestamp_srcip:srcport-dstip:dstport

// Since we first separately extract time
// by calling get_time_from_httpreq_fname on the same string
// we can directly get to the tcp_tuple string
/*
    char* httptok = strtok(fname, "_");
    if(httptok == NULL || strcmp(httptok,HTTPREQLIST_PREFIX, strlen(HTTPREQLIST_PREFIX))!=0)
        return NULL;

    strtok(NULL, "_"); // skip timestamp
*/
    char* tcp_tuple = strtok(NULL, "_");

    if(tcp_tuple == NULL)
        return NULL;

    char* srcip = strtok(tcp_tuple, ":");
    return srcip;   
}

time_t get_time_from_httpreq_fname(char* fname) {
    //fname format:
    //httpreqlist-trigger_timestamp_srcip:srcport-dstip:dstport

    char* httptok = strtok(fname, "_");
    if(httptok == NULL || strncmp(httptok,HTTPREQLIST_PREFIX,strlen(HTTPREQLIST_PREFIX))!=0)
        return 0;

    char* ts = strtok(NULL, "_");

    return (time_t)atol(ts);
}

ghash_table_t* init_httpreq_triggers_ht(char* triggers_fname) {
    // read triggers (domain names) from triggers_fname file

    #define TRIGGERS_HT_LEN 1000
    ghash_table_t* ht = ght_init(TRIGGERS_HT_LEN,true,false,true,false,0,NULL,NULL);

    // open and read triggers_fname line by line
    FILE* f = fopen(triggers_fname, "rt");
    char line[MAX_HOST_LEN+1];

    printf("Reading trigger host names from: %s\n", triggers_fname);
    while(fgets(line,MAX_HOST_LEN,f) != NULL) {
        line[MAX_HOST_LEN] = '\0';

        // strip \n
        size_t l = strnlen(line,MAX_HOST_LEN);
        if(line[l-1] == '\n')
            line[l-1] = '\0';

        printf("Inserting trigger host into HT: %s\n", line);
        ght_insert(ht,line,NULL);
    }

    if (ferror(f)) {
        perror("Error while reading triggers_fname file");
        return NULL;
    }

    return ht;
}

void *notify_httpreq_match_thread(void* fname) {
    create_dev_shm_tmp_file(fname);
    sleep(3);
    remove_dev_shm_tmp_file(fname);
    free(fname);
    pthread_exit(NULL);
}

///////////////////////////////////////////

bool str_starts_with(char* s1, char* s2) {
    char* s = strstr(s1,s2);
    return (s == s1);
}
