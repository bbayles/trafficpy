from collections import defaultdict
from os import initgroups, setgid, setuid
from pwd import getpwnam
from queue import Empty, Queue
from socket import inet_ntop, AF_INET, AF_INET6
from threading import Event, Thread

from ffi import ffi, libpcap
from network_structs import (
    ethernet_header,
    ethernet_q_header,
    ethernet_qq_header,
    icmp_header,
    ipv4_header,
    ipv6_header,
    tcp_header,
    udp_header,
)


class MetadataStats(object):
    __slots__ = [
        'start_ts', 'end_ts', 'packet_count', 'byte_count', 'tcp_flags'
    ]

    def __init__(self):
        self.start_ts = 2147483647  # 2038-01-19 03:14:07
        self.end_ts = 0  # 1970-01-01 00:00:00
        self.packet_count = 0
        self.byte_count = 0
        self.tcp_flags = 0

    def update(self, time_stamp, byte_count, tcp_flags):
        if time_stamp < self.start_ts:
            self.start_ts = time_stamp

        if time_stamp > self.end_ts:
            self.end_ts = time_stamp

        self.packet_count += 1
        self.byte_count += 1
        self.tcp_flags |= tcp_flags


flow_stats = defaultdict(lambda: defaultdict(MetadataStats))
fragment_holder = {}
packet_queue = Queue(maxsize=0)
stop_event = Event()


def drop_privileges(target_user):
    user_data = getpwnam(target_user)
    initgroups(target_user, user_data.pw_gid)
    setgid(user_data.pw_gid)
    setuid(user_data.pw_uid)
    print('Dropped privileges to {}'.format(target_user))


@ffi.callback('void(u_char *, const struct pcap_pkthdr *, const u_char *)')
def hook(user, pkt_header, pkt_data):
    global packet_queue

    # Timestamps
    seconds = pkt_header.ts.tv_sec
    microseconds = pkt_header.ts.tv_usec

    # Bytes in the capture and total bytes
    captured_length = pkt_header.caplen
    packet_length = pkt_header.len
    pkt_data = ffi.buffer(pkt_data, captured_length)[:]

    data = (seconds, microseconds, captured_length, packet_length, pkt_data)
    packet_queue.put_nowait(data)


def set_filter(handle, bpf_expression):
    program = ffi.new('struct bpf_program *')
    expression = ffi.new('const char[]', bpf_expression)
    optimize = 1
    netmask = libpcap.PCAP_NETMASK_UNKNOWN
    libpcap.pcap_compile(handle, program, expression, optimize, netmask)
    libpcap.pcap_setfilter(handle, program)


# Run as root!
def live_capture(
    device,
    packet_limit=-1,
    snaplen=128,
    drop_to_user=None,
    bpf_expression=None,
):
    source = ffi.new('const char[]', device)
    errbuf = ffi.new('char[]', libpcap.PCAP_ERRBUF_SIZE)
    handle = libpcap.pcap_create(source, errbuf)
    libpcap.pcap_set_snaplen(handle, snaplen)
    libpcap.pcap_activate(handle)

    if bpf_expression is not None:
        set_filter(handle, bpf_expression)

    if drop_to_user is not None:
        drop_privileges(drop_to_user)

    try:
        libpcap.pcap_loop(handle, packet_limit, hook, ffi.NULL)
    finally:
        libpcap.pcap_close(handle)
        stop_event.set()
        print('Live capture completed.')


def file_capture(file_path, bpf_expression=None):
    source = ffi.new('const char[]', file_path)
    errbuf = ffi.new('char[]', libpcap.PCAP_ERRBUF_SIZE)
    handle = libpcap.pcap_open_offline(source, errbuf)

    if bpf_expression is not None:
        set_filter(handle, bpf_expression)

    try:
        libpcap.pcap_loop(handle, -1, hook, ffi.NULL)
    finally:
        libpcap.pcap_close(handle)
        stop_event.set()
        print('File capture completed.')


def read_data():
    global flow_stats
    global packet_queue
    global stop_event

    packet_count = 0

    while True:
        # Retrieve a packet, or break out if everything is finished
        try:
            data = packet_queue.get(timeout=1)
        except Empty:
            if stop_event.is_set():
                break
            continue

        seconds, microseconds, captured_length, packet_length, pkt_data = data

        # Inspect the Ethernet header to determine where the layer 3 data
        # starts and what type it is.-
        # ether_type 0x8100 has a VLAN tag (802.1Q)
        # ether_type 0x88A8 and 0x9100 have two VLAN tags (Q-in-Q)
        ether_type = ethernet_header.unpack_from(pkt_data, 0)[-1]
        l3_offset = ethernet_header.size
        if ether_type == 0x8100:
            ether_type = ethernet_q_header.unpack_from(pkt_data, 0)[-1]
            l3_offset = ethernet_q_header.size
            print('Q tagging detected')
        elif (ether_type == 0x88A8) or (ether_type == 0x9100):
            ether_type = ethernet_qq_header.unpack_from(pkt_data, 0)[-1]
            l3_offset = ethernet_qq_header.size
            print('Q-in-Q tagging detected')

        # Inspec the IP header to determine where the layer 4 data starts and
        # what type it is.
        # ether_type 0x0800 is IPv4
        # ether_type 0x86dd is IPv6
        more_fragments = 0
        frag_offset = 0
        if ether_type == 0x0800:
            address_family = AF_INET
            ip_data = ipv4_header.unpack_from(pkt_data, l3_offset)

            version_ihl = ip_data[0][0]
            version = ip_data[0][0] >> 4
            if version != 4:
                print('IP version did not match EtherType')

            protocol = ip_data[6]

            ihl = version_ihl & 0x0F
            l4_offset = l3_offset + (ihl * 4)

            frag_key = ip_data[3]
            frag_info = ip_data[4]
            more_fragments = (frag_info >> 13) & 0b001
            frag_offset = frag_info & 0x1FFF
        elif ether_type == 0x86dd:
            address_family = AF_INET6
            ip_data = ipv6_header.unpack_from(pkt_data, l3_offset)

            version = ip_data[0][0] >> 4
            if version != 6:
                print('IP version did not match EtherType')

            protocol = ip_data[2]

            l4_offset = l3_offset + ipv6_header.size
        else:
            print('Unrecognized L3 type {}'.format(ether_type))
            continue

        # Not part of a fragment, and nothing left
        if (not frag_offset) and (not more_fragments):
            pass
        # The first part of a fragment
        elif (not frag_offset) and more_fragments:
            frag_value = frag_offset, pkt_data[l4_offset:]
            fragment_holder[frag_key] = [frag_value]
            continue
        # The last part of a fragment
        elif frag_offset and (not more_fragments):
            frag_value = frag_offset, pkt_data[l4_offset:]
            fragment_holder[frag_key].append(frag_value)

            frag_parts = sorted(fragment_holder[frag_key])
            assembled = b''.join(x[1] for x in frag_parts)

            del fragment_holder[frag_key]
        # The middle of a fragment
        elif frag_offset and more_fragments:
            frag_value = frag_offset, pkt_data[l4_offset:]
            fragment_holder[frag_key].append(frag_value)
            continue

        tcp_flags = 0
        # TCP
        if protocol == 0x06:
            l4_data = tcp_header.unpack_from(pkt_data, l4_offset)
            flag_data = l4_data[4]
            tcp_flags = ((flag_data[0] & 0x01) << 8) ^ flag_data[1]
        # UDP
        elif protocol == 0x11:
            l4_data = udp_header.unpack_from(pkt_data, l4_offset)
        # ICMP or ICMPv6
        elif (protocol == 0x01) or (protocol == 0x3a):
            l4_data = icmp_header.unpack_from(pkt_data, l4_offset)
        else:
            print('Unrecognized L4 header {}'.format(protocol))
            continue

        src_ip = ip_data[-2]
        dst_ip = ip_data[-1]
        src_port = l4_data[0]
        dst_port = l4_data[1]

        time_key = (seconds // 10) * 10
        flow_key = (
            inet_ntop(address_family, src_ip),
            inet_ntop(address_family, dst_ip),
            src_port,
            dst_port,
            protocol,
        )
        flow_stats[time_key][flow_key].update(
            seconds, packet_length, tcp_flags
        )

        # print(*flow_key, sep='\t')
        packet_count += 1

    print('Reader loop completed. Read {} packets'.format(packet_count))


if __name__ == '__main__':
    reader_thread = Thread(target=read_data)
    reader_thread.start()

    capture_thread = Thread(
        target=file_capture,
        kwargs={
            'file_path': b'/home/bo/Downloads/pcap-test.pcap',
            'bpf_expression': b'ip',
        },
    )
    capture_thread.start()
