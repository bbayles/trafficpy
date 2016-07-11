from cffi import FFI

ffi = FFI()
libpcap = ffi.dlopen('/home/bo/Code/bbcap/libpcap/libpcap.so.1.7.4')

cdefs = """
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_ERRBUF_SIZE 256
#define PCAP_IF_LOOPBACK	0x00000001
#define MODE_CAPT 0
#define MODE_STAT 1

#define PCAP_NETMASK_UNKNOWN 0xffffffff

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short int u_short;

typedef int bpf_int32;
typedef u_int bpf_u_int32;
typedef struct pcap_dumper pcap_dumper_t;

typedef long int __time_t;
typedef long int __suseconds_t;

typedef struct pcap pcap_t;
typedef struct pcap_addr pcap_addr_t;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef void (*pcap_handler)(
    u_char *, const struct pcap_pkthdr *, const u_char *
);

struct pcap_if {
    struct pcap_if *next;
    char *name;
    char *description;
    struct pcap_addr *addresses;
    bpf_u_int32 flags;
};

struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
};

struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;
    bpf_u_int32 sigfigs;
    bpf_u_int32 snaplen;
    bpf_u_int32 linktype;
};

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};

struct pcap_stat {
    u_int ps_recv;
    u_int ps_drop;
    u_int ps_ifdrop;
};

struct bpf_insn {
    u_short code;
    u_char jt;
    u_char jf;
    bpf_u_int32 k;
};

struct bpf_program {
    u_int bf_len;
    struct bpf_insn *bf_insns;
};

typedef struct pcap_if pcap_if_t;

int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf);
void pcap_freealldevs(pcap_if_t *alldevs);

pcap_t *pcap_create(const char *source, char *errbuf);
pcap_t *pcap_open_offline(const char *fname, char *errbuf);
int pcap_activate(pcap_t *);
void pcap_close(pcap_t *p);

int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
void pcap_breakloop(pcap_t *);

int pcap_set_buffer_size(pcap_t *p, int buffer_size);
int pcap_set_promisc(pcap_t *p, int promisc);
int pcap_can_set_rfmon(pcap_t *p);
int pcap_set_rfmon(pcap_t *p, int rfmon);
int pcap_set_snaplen(pcap_t *p, int snaplen);
int pcap_set_timeout(pcap_t *p, int to_ms);
int pcap_set_tstamp_type(pcap_t *p, int tstamp_type);

int pcap_compile(
    pcap_t *p,
    struct bpf_program *fp,
    const char *str,
    int optimize,
    bpf_u_int32 netmask
);
int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
"""

ffi.cdef(cdefs)
