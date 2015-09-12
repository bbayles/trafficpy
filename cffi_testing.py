from os import initgroups, setgid, setuid
from pwd import getpwnam
from queue import Empty, Queue
from socket import inet_ntoa
from threading import Event, Thread

from ffi import ffi, libpcap
from network_structs import (
    ethernet_header,
    icmp_header,
    ipv4_header,
    tcp_header,
    udp_header,
)

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
            else:
                continue

        seconds, microseconds, captured_length, packet_length, pkt_data = data

        # Determine where the layer 3 data starts
        src_mac, dst_mac, ether_type = ethernet_header.unpack_from(pkt_data, 0)

        if ether_type == 0x0800:  # Normal Ethernet
            l3_offset = ethernet_header.size + 0
        elif ether_type == 0x8100:  # 802.1q VLAN tag
            l3_offset = ethernet_header.size + 4
        elif ether_type == 0x88A8:  # 802.1ad S-tag and C-tag
            l3_offset = ethernet_header.size + 8
        elif ether_type == 0x9100:  # Earlier QinQ version
            l3_offset = ethernet_header.size + 8
        else:
            print('Unrecognized L2 header {}'.format(ether_type))
            continue

        ip_data = ipv4_header.unpack_from(pkt_data, l3_offset)

        # Verify IPv4
        version_ihl = ip_data[0][0]
        version = version_ihl >> 4
        if version != 4:
            print('Unrecognized IP version')
            continue

        # Determine where the layer 4 data starts and what type it is
        ihl = version_ihl & 0x0F
        l4_offset = l3_offset + (ihl * 4)

        protocol = ip_data[6]
        if protocol == 0x01:
            l4_header = icmp_header
        elif protocol == 0x06:
            l4_header = tcp_header
        elif protocol == 0x11:
            l4_header = udp_header
        else:
            print('Unrecognized L4 header {}'.format(protocol))
            continue

        l4_data = l4_header.unpack_from(pkt_data, l4_offset)

        # Extract the relevant data
        src_ip = ip_data[8]
        dst_ip = ip_data[9]
        src_port = l4_data[0]
        dst_port = l4_data[1]

        # flag_data is two bytes. The last bit of the first byte has the NS
        # flag. The second byte has the other 8 flags.
        flag_data = l4_data[4]
        flags = ((flag_data[0] & 0x01) << 8) ^ flag_data[1]

        packet = (
            seconds,
            microseconds,
            inet_ntoa(src_ip),
            inet_ntoa(dst_ip),
            protocol,
            src_port,
            dst_port,
            flags,
            packet_length,
        )

        print(*packet, sep='\t')
        packet_count += 1

    print('Reader loop completed. Read {} packets'.format(packet_count))


if __name__ == '__main__':
    reader_thread = Thread(target=read_data)
    reader_thread.setDaemon(True)
    reader_thread.start()

    # capture_thread = Thread(target=live_capture, args=(b'wlan0', 10))
    capture_thread = Thread(
        target=file_capture,
        args=(b'/home/bo/Downloads/pcap-test.pcap',),
        kwargs={'bpf_expression': b'tcp'},
    )
    capture_thread.start()
