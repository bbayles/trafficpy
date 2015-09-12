from cffi import FFI

ffi = FFI()
libpcap = ffi.dlopen('/home/bo/Code/bbcap/libpcap/libpcap.so.1.8.0-PRE-GIT')

cdefs = """
#define PCAP_ERRBUF_SIZE 256
#define PCAP_NETMASK_UNKNOWN 0xffffffff

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short int u_short;

typedef u_int bpf_u_int32;

typedef long int __time_t;
typedef long int __suseconds_t;

typedef struct pcap pcap_t;


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

struct pcap_pkthdr {
    struct timeval ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
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
