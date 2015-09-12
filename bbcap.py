from ffi import ffi, libpcap


def get_all_devices():
    alldevsp = ffi.new('pcap_if_t **')
    errbuf = ffi.new('char[]', libpcap.PCAP_ERRBUF_SIZE)

    try:
        rc = libpcap.pcap_findalldevs(alldevsp, errbuf)
        if rc:
            raise RuntimeError(ffi.string(errbuf))

        all_devices = []
        dev = alldevsp[0]
        while dev:
            all_devices.append(ffi.string(dev.name))
            dev = dev.next
    finally:
        libpcap.pcap_freealldevs(alldevsp[0])

    return all_devices
